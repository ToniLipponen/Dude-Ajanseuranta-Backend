#include "include/Application.h"
#include "include/Crypt.h"
#include "include/Util.h"
#include "include/Logging.h"
#include "include/Config.h"

Application::Application()
{
    // Get driver instance
    driver = sql::mariadb::get_driver_instance();

    if(!driver)
    {
        throw std::runtime_error("Failed to get sql driver instance");
    }

    /// TODO: Put these in Config.h
    sql::SQLString url("jdbc:mariadb://localhost:3306/DudeWorktimeManagement");
    sql::Properties properties({{"user", "toni"}, {"password", "toni"}});

    connection = driver->connect(url, properties);
    houseKeepingConnection = driver->connect(url, properties);

    if(!connection)
    {
        throw std::runtime_error("Failed to connect to database");
    }

    MakeQuery("CREATE TABLE IF NOT EXISTS admins ("
              "id INT NOT NULL AUTO_INCREMENT, "
              "name VARCHAR(64), "
              "passwd BINARY(64), "
              "salt VARCHAR(64), PRIMARY KEY(id))");

    MakeQuery("CREATE TABLE IF NOT EXISTS users ("
              "id INT NOT NULL AUTO_INCREMENT, "
              "name VARCHAR(64), "
              "cardID INT, "
              "present INT DEFAULT 0, "
              "active INT, PRIMARY KEY(id))");

    MakeQuery("CREATE TABLE IF NOT EXISTS cards ("
              "id INT NOT NULL AUTO_INCREMENT, "
              "name VARCHAR(64), "
              "cardID INT, PRIMARY KEY(id))");

    MakeQuery("CREATE TABLE IF NOT EXISTS times ("
              "id INT NOT NULL AUTO_INCREMENT,"
              "userID int, "
              "beginTime DATETIME DEFAULT CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+02:00'), "
              "endTime DATETIME, "
              "forgotLogout INT DEFAULT 0,"
              "PRIMARY KEY(id))");

    MakeQuery("CREATE TABLE IF NOT EXISTS tokens ("
              "adminName VARCHAR(64),"
              "hash BINARY(64), "
              "validUntil TIMESTAMP)");

#if defined(FRONTEND_MOUNTPOINT)
    this->set_base_dir(FRONTEND_MOUNTPOINT);

    for(const auto& mountPoint : mountPoints)
    {
        this->set_mount_point(mountPoint.first, mountPoint.second);
    }
#endif

    std::cout << "Connected to database" << std::endl;

    AddAdmin("admin", "admin");
    houseKeepingThread = std::thread([&](){ HouseKeeping();});
    houseKeepingThread.detach();

    SetRoutes();

    this->set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res)
    {
        for(const auto& header : headers)
        {
            res.set_header(header.first, header.second);
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });

#ifndef NO_LOGGING
    this->set_logger([&](const httplib::Request &req, const httplib::Response &res) {
        printf("%s", log(req, res).c_str());
    });
#endif

    if(!this->listen("0.0.0.0", 8082))
    {
        throw std::runtime_error("Server failed to listen");
    }
}

int64_t Application::GetTokenValidTime(const std::string& tokenString)
{
    auto bytes = HashToken(tokenString);
    auto result = MakeQuery("SELECT TIMESTAMPDIFF(second, NOW(), validUntil) as validSeconds "
                            "FROM tokens WHERE hash = ?", bytes);

    if(result && result->rowsCount())
    {
        result->next();
        return std::max<int64_t>(result->getInt64("validSeconds"), 0);
    }

    return 0;
}

bool Application::ValidateToken(const std::string& token)
{
    auto bytes = HashToken(token);
    auto result = MakeQuery("SELECT * FROM tokens WHERE hash=?", bytes);

    return result->rowsCount() > 0;
}

void Application::RemoveToken(const std::string& token)
{
    auto tokenHash = HashToken(token);
    MakeQuery("DELETE FROM tokens WHERE hash = ?", tokenHash);
}

void Application::AddToken(const std::string& user, const std::string& token, int validSeconds)
{
    auto tokenHash = HashToken(token);

    MakeQuery("INSERT INTO tokens (adminName, hash, validUntil) "
        "VALUES (?,?,TIMESTAMPADD(second, ?, NOW()))", user, tokenHash, validSeconds);
}

void Application::AddAdmin(const std::string& username, const std::string& password)
{
    if(!AdminExists(username))
    {
        auto salt = GenerateToken();
        auto passwordHash = HashPassword(password, salt);

        // Todo make sure there are no duplicate users
        MakeQuery(
            "INSERT INTO admins (name, passwd, salt) " 
            "VALUES (?, ?, ?) ",
            username, 
            passwordHash, 
            salt);
    }
}

bool Application::AuthenticateWithPassword(const std::string& username, const std::string& password)
{
    auto saltResult = MakeQuery("SELECT salt FROM admins WHERE name = ?", username);

    saltResult->next();
    std::string salt = saltResult->getString("salt").c_str();

    auto passwordHash = HashPassword(password, salt);
    auto idResult = MakeQuery("SELECT id "
    " FROM admins WHERE name=? AND passwd=?", username, passwordHash);

    return (idResult && idResult->rowsCount() > 0);
}

void Application::ChangeUserPasswordWithToken(const std::string& token, const std::string& newPass)
{
    auto username = GetTokenUser(token);
    auto newSalt = GenerateToken();
    auto passwdHash = HashPassword(newPass, newSalt);

    MakeQuery("DELETE FROM tokens WHERE adminName=?", username);
    MakeQuery("UPDATE admins SET passwd = ?, salt = ? WHERE name = ?", passwdHash, newSalt, username);
}

json Application::GetCardsList()
{
    auto res = MakeQuery("SELECT C.id as cardID, C.name as cardName, U.name as assignedTo "
                         "FROM cards as C LEFT JOIN users as U on C.id = U.cardID");

    if(!res || res->rowsCount() == 0)
    {
        // throw std::runtime_error("Invalid request");
        return {};
    }

    json data = json::array();
    
    while(res->next())
    {
        std::string cardname    = res->getString("cardName").c_str();
        int32_t cardid          = res->getInt("cardID");
        std::string assignedTo  = res->getString("assignedTo").c_str();

        data.push_back({
            {"cardname",    cardname},
            {"cardid",      cardid},
            {"assingedto",  assignedTo}});
    }

    return data;
}

json Application::GetUsersData(std::optional<int> userID)
{
    std::unique_ptr<sql::ResultSet> res;

    if(userID)
    {
        res = MakeQuery(
            "SELECT U.id, U.name, C.name as cardName, U.active, U.present "
            "FROM users AS U "
            "LEFT JOIN cards as C on U.cardID = C.id "
            "WHERE U.id = ?", *userID);
    }
    else
    {
        res = MakeQuery(
            "SELECT U.id, U.name, C.name as cardName, U.active, U.present "
            "FROM users AS U " 
            "LEFT JOIN cards as C on U.cardID = C.id");
    }

    json data = json::array();

    while(res->next())
    {
        int32_t id              = res->getInt("id");
        std::string name        = res->getString("name").c_str();
        std::string cardname    = res->getString("cardName").c_str();
        int32_t active          = res->getInt("active");
        int32_t present         = res->getInt("present");

        data.push_back({
            {"id",          id},
            {"cardname",    cardname},
            {"name",        name},
            {"present",     present},
            {"active",      active}});
    }

    return data;
}


/// TODO: Check if user exists

int Application::RemoveUser(int id)
{
    try
    {
        MakeQuery("DELETE FROM users WHERE id=?", id);
    }
    catch(...)
    {

    }
    
    return 0;
}

int Application::RemoveCard(int id)
{
    MakeQuery("DELETE FROM cards WHERE id=?", id);

    return 0;
}

int Application::RenameCard(int cardID, const std::string& cardname)
{
    MakeQuery("UPDATE cards SET name = ? WHERE id = ?", cardname, cardID);

    return 0;
}

int Application::PounchCard(int cardID)
{
    auto result = MakeQuery("SELECT id FROM cards WHERE cardID=?", cardID);

    if(result->rowsCount() == 0)
    {
        return 1;
    }
    else
    {
        result->next();
        int cardID = result->getInt("id");
        auto idResult = MakeQuery("SELECT id FROM users WHERE cardID=?", cardID);

        if(!idResult || idResult->rowsCount() == 0)
        {
            std::cout << "This card has not been assigned to anyone\n";
            return 2;
        }

        idResult->next();
        int id = idResult->getInt("id");
        
        if(MakeQuery("SELECT * FROM times WHERE endTime IS NULL AND userID = ?", id)->rowsCount())
        {
            MakeQuery("UPDATE times " 
	                "SET endTime = CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+02:00') "
                    "WHERE endTime IS null AND userID = ?;", id);
        }
        else
        {
            MakeQuery("INSERT INTO times (userID) values(?)", id);
        }

        MakeQuery("UPDATE users SET present = !present WHERE id = ?", id);
    }

    return 0;
}

int Application::AddCard(int cardID)
{
    if(MakeQuery("SELECT * FROM cards WHERE cardID=?", cardID)->rowsCount() == 0)
    {
        MakeQuery("INSERT INTO cards (name, cardID) VALUES (?, ?)", "Unnamed card" + std::to_string(cardID), cardID);
    }
    else
    {
        return 1;
    }
    
    return 0;
}

int Application::SetUserActive(int userID, int isActive)
{
    MakeQuery("UPDATE users SET active = ? WHERE id = ?", static_cast<int>(isActive > 0), userID);

    return 0;
}

std::string Application::GetTokenUser(const std::string& token)
{
    auto tokenHash = HashToken(token);
    auto res = MakeQuery("SELECT adminName FROM tokens WHERE hash = ?", tokenHash);

    if(!res || res->rowsCount() == 0)
    {
        return {};
    }

    res->next();
    return res->getString("adminName").c_str();
}

bool Application::AdminExists(const std::string& username)
{
    auto result = MakeQuery("SELECT id FROM admins WHERE name = ?", username);

    return (result && result->rowsCount());
}

json Application::GetAdminsData(std::optional<int> adminID)
{
    std::unique_ptr<sql::ResultSet> res;

    if(adminID)
    {
        res = MakeQuery(
            "SELECT * "
            "FROM admins " 
            "WHERE id = ? ", 
            *adminID);
    }
    else
    {   
        res = MakeQuery(
            "SELECT * "
            "FROM admins");
    }

    json data = json::array();

    while(res->next())
    {
        int32_t id          = res->getInt("id");
        std::string name    = res->getString("name").c_str();

        data.push_back({
            {"id",  id},
            {"name",name}});
    }

    return data;
}
