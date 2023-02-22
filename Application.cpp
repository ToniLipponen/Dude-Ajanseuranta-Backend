#include "Application.h"
#include "Crypt.h"
#include "Util.h"
#include "Config.h"
#include <csv.hpp>

std::string dump_headers(const httplib::Headers &headers) {
  std::string s;
  char buf[BUFSIZ];

  for (auto it = headers.begin(); it != headers.end(); ++it) {
    const auto &x = *it;
    snprintf(buf, sizeof(buf), "%s: %s\n", x.first.c_str(), x.second.c_str());
    s += buf;
  }

  return s;
}

std::string log(const httplib::Request &req, const httplib::Response &res) {
  std::string s;
  char buf[BUFSIZ];

  s += "================================\n";

  snprintf(buf, sizeof(buf), "%s %s %s", req.method.c_str(),
           req.version.c_str(), req.path.c_str());
  s += buf;

  std::string query;
  for (auto it = req.params.begin(); it != req.params.end(); ++it) {
    const auto &x = *it;
    snprintf(buf, sizeof(buf), "%c%s=%s",
             (it == req.params.begin()) ? '?' : '&', x.first.c_str(),
             x.second.c_str());
    query += buf;
  }
  snprintf(buf, sizeof(buf), "%s\n", query.c_str());
  s += buf;

  s += dump_headers(req.headers);

  s += "--------------------------------\n";

  snprintf(buf, sizeof(buf), "%d %s\n", res.status, res.version.c_str());
  s += buf;
  s += dump_headers(res.headers);
  s += "\n";

  if (!res.body.empty()) { s += res.body; }

  s += "\n";

  return s;
}

int Application::Run()
{
    // Get driver instance 
    driver = sql::mariadb::get_driver_instance();

    if(!driver)
    {
        std::cerr << "Failed to get sql driver instance\n";
        return 1;
    }

    // Make connection to the database
    // TODO: Take properties from ENV
    sql::SQLString url("jdbc:mariadb://localhost:3306/DudeWorktimeManagement");
    sql::Properties properties({{"user", "toni"}, {"password", "toni"}});

    connection = driver->connect(url, properties);
    houseKeepingConnection = driver->connect(url, properties);

    if(!connection)
    {
        std::cerr << "Failed to connect to database\n";
        return 2;
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
            "beginTime DATETIME DEFAULT CURRENT_TIMESTAMP(), "
            "endTime DATETIME, "
            "forgotLogout INT DEFAULT 0,"
            "PRIMARY KEY(id))");

    MakeQuery("CREATE TABLE IF NOT EXISTS tokens ("
            "adminName VARCHAR(64),"
            "hash BINARY(64), "
            "validUntil TIMESTAMP)");

    // Todo match int, this is userID
    this->Get("/api/v1/user/times/(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        std::string token;
        json data;
        
        if(!ValidateRequest(request, response, token, data))
            return;

        if(ValidateToken(token))
        {

            /*
                SELECT *
                FROM example
                ORDER BY example_date ASC;
            */

            std::string userIDString = request.matches[1];
            int userID = std::stoi(userIDString);

            auto res = MakeQuery("SELECT "
            "UNIX_TIMESTAMP(beginTime) as ubeginTime, " 
            "UNIX_TIMESTAMP(endTime) as uendTime "
            "FROM  times WHERE userID = ? "
            "ORDER BY beginTime DESC", userID);
            json rdata = json::array();

            while(res->next())
            {
                int beginTime = res->getInt("ubeginTime");
                int endTime = res->getInt("uendTime");

                rdata.push_back({{"begin_time", beginTime}, {"end_time", endTime}});
            }

            response.body = rdata.dump();
        }
        else
        {
            response.status = 401; /// Unauthorized
            return;
        }
    });

    /// Pounch in/out
    // TODO: Respond pounch in / pounch out with different message.
    
    /**
     * {pounch_in: 1}
     * */ 
    this->Post("/api/v1/card/read", [&](const httplib::Request& request, httplib::Response& response)
    {
        int uid = 0;
        try
        {
            json data = json::parse(request.body);
            uid = data.at("uid");
        }
        catch(std::exception& e)
        {
            response.status = 419;
            response.body = json({{"error_message", "Failed to parse json"}}).dump();
            return;
        }

        if(addingCard)
        {
            if(AddCard(uid) != 0)
            {
                response.status = 420;
                response.body = json({{"error_message", "Card already exists"}}).dump();
                return;
            }
        }
        else
        {
            if(PounchCard(uid) != 0)
            {
                response.status = 421;
                response.body = json({{"error_message", "Card doesn't exist"}}).dump();
                return;
            }
        }
    });

    this->Get("/api/v1/validate", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;
        
        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        auto seconds = GetTokenValidTime(token);
        json responseData({"validSeconds", seconds});

        response.body = responseData.dump();
    });

    this->Post("/api/v1/logout", [&](const httplib::Request& request, httplib::Response& response)
    {
        /// This might throw, but I don't care. 
        /// Httplib is going to catch and log it anyway.
        /// This is not an issue.

        auto 🍪  = "Cookie";
        auto token = GetTokenFromString(request.get_header_value(🍪));

        if(!token)
        {
            response.status = 400;
            return;
        }

        RemoveToken(*token);
    });

    this->Post("/api/v1/login", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string username, password;
        bool remember = 0;

        try {
            data = json::parse(request.body);

            username = data.at("username");
            password = data.at("password");
            remember = data.at("remember");
        }
        catch(std::exception e) {
            response.status = 400; // Bad request
            response.body = "{\"error_message\": \"Request body did not contain valid json data.\"}";
            return;
        }

        if(!AuthenticateWithPassword(username, password))
        {
            response.status = 403; // Forbidden
            response.body = "{\"error_message\": \"Access denied\"}";
            return;
        }

        auto token = GenerateToken();
        AddToken(username, token, (remember ? 604800 : 30));
        response.set_header("Set-Cookie", "token=" + token + " ;SameSite=None");
    });

    this->Post("/api/v1/changepassword", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;
        
        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        std::string currentPass, newPass;
        try
        {
            newPass = data.at("newpass");
            currentPass = data.at("currentpass");
        }
        catch(std::exception& e)
        {
            response.status = 400;
            response.body = json({{"error_message", e.what()}}).dump();
            return;
        }

        try
        {
            ChangeUserPasswordWithToken(token, newPass);
        }
        catch(std::exception& e)
        {
            response.status = 500;
            response.body = json({{"error_message", e.what()}}).dump();
            return;
        }
    });

    this->Get("/api/v1/card/get", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;
        
        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        auto cards = GetCardsList();

        response.body = cards.dump();
        std::cout << response.body << std::endl;
    });

    this->Post("/api/v1/card/readingmode/(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        const std::string state = request.matches[1];
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        addingCard = (state == "start");
        std::cout << "Adding mode: " << addingCard << std::endl; 

        if(addingCard)
        {
            cardAddingClock.Reset();
        }
    });

    this->Post("/api/v1/user/add", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        std::string username, cardname;

        try
        {
            username = data.at("username");
            // cardname = data.at("cardname");
        }
        catch(std::exception& e)
        {
            response.status = 400;
            response.body = json({{"error_message", e.what()}}).dump();
            return;
        }

        AddUser(username, cardname);
    });

    this->Post("/api/v1/user/updatecard", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        std::string cardname;
        int userID = 0;

        try
        {
            userID = data.at("userid");
            cardname = data.at("cardname");
        }
        catch(std::exception& e)
        {
            response.status = 400;
            response.body = json({{"error_message", e.what()}}).dump();
            return;
        }

        UpdateUser(userID, cardname);
    });

    this->Get("/api/v1/users/get", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        auto result = GetUsersData();
        if(result.empty())
        {
            response.body = "{}";
        }
        else
        {
            response.body = result.dump();
        }
    });

    this->Get("/api/v1/user/get/(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        std::string userIDString = request.matches[1];
        
        if(userIDString.empty())
        {
            response.status = 400;
            response.body = json({{"error_message", "No user id in path"}}).dump();
            return;
        }

        auto result = GetUsersData(std::stoi(userIDString));

        if(result.empty())
        {
            response.body = "{}";
        }
        else
        {
            response.body = result.dump();
        }
    });

    this->Get("/api/v1/admins/get", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        auto result = GetAdminsData();

        if(result.empty())
        {
            response.body = "{}";
        }
        else
        {
            response.body = result.dump();
        }
    });

    this->Get("/api/v1/admin/get/(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        std::string adminIDString = request.matches[1];
        
        if(adminIDString.empty())
        {
            response.status = 400;
            response.body = json({{"error_message", "No user id in path"}}).dump();
            return;
        }

        auto result = GetAdminsData(std::stoi(adminIDString));
        response.body = result.dump();
    });

    this->Post("/api/v1/admin/add", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        // TODO: Put these in a try catch block, and return a specific error if fails
        std::string username = data.at("username");
        std::string password = data.at("password");

        AddAdmin(username, password);
    });

    this->Post("/api/v1/user/remove", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        /// TODO: Check if id exists
        int id = data.at("id");

        RemoveUser(id);
    });

    this->Post("/api/v1/card/remove", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        int id;
        
        try
        {
            id = data.at("id");
            RemoveCard(id);
        }
        catch(std::exception& e)
        {
            response.status = 400;
            response.body = json({{"error_message", e.what()}});
            return;
        }
    });

    this->Post("/api/v1/card/rename", [&](const httplib::Request& request, httplib::Response& response)
    {
        std::string token;
        json data;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }
        
        std::string cardID;
        std::string cardname;
        
        try
        {
            cardID = data.at("cardid");
            cardname = data.at("cardname");
        }
        catch(std::exception& e)
        {
            response.status = 400;
            response.body = json({{"error_message", e.what()}});
        }

        int cardIDInt = std::stoi(cardID);

        RenameCard(cardIDInt, cardname);
    });

    this->Post("/api/v1/user/setactive", [&](const httplib::Request& request, httplib::Response& response)
    {
        int userID, isActive;
        std::string token;
        json data;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        SetUserActive(userID, isActive);
    });

    this->Post("/api/v1/user/setpresent", [&](const httplib::Request& request, httplib::Response& response)
    {
        const std::string token = request.get_header_value("token");
    });

    this->Get("/api/v1/user/gettimescsv/(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        std::string token;
        json data;
        
        if(!ValidateRequest(request, response, token, data))
            return;

        if(ValidateToken(token))
        {
            std::string userIDString = request.matches[1];
            int userID = std::stoi(userIDString);

            auto res = MakeQuery("SELECT UNIX_TIMESTAMP(beginTime) as ubeginTime, UNIX_TIMESTAMP(endTime) as uendTime from times WHERE userID = ?", userID);
            json rdata = json::array();
            std::stringstream ss;

            csv::DelimWriter<std::stringstream, ';', '"', true> writer(ss);
            writer <<  std::vector<std::string>{"begin time", "end time", "hours total"};

            while(res->next())
            {
                int beginTime = res->getInt("ubeginTime");
                int endTime = res->getInt("uendTime");

                rdata.push_back({{"begin_time", beginTime}, {"end_time", endTime}});
            }

            response.body = rdata.dump();
        }
        else
        {
            response.status = 401; /// Unauthorized
            return;
        }
    });

    this->Options("(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        response.set_header("Access-Control-Allow-Headers", FRONT_END_ORIGIN);
    });

    this->set_base_dir("./dude-worktime-frontend/dist");
    this->set_mount_point("/login", "/login");
    this->set_mount_point("/admin", "/admin");
    this->set_mount_point("/cards", "/cards");
    this->set_mount_point("/user", "/user");
    this->set_mount_point("/users", "/users");
    
    std::cout << "Connected to database" << std::endl;

    AddAdmin("admin", "admin");
    houseKeepingThread = std::thread([&](){ HouseKeeping();});
    houseKeepingThread.detach();

    this->set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res)
    {
        res.set_header("Access-Control-Allow-Origin", FRONT_END_ORIGIN);
        res.set_header("Access-Control-Allow-Credentials", FRONT_END_ALLOW_CREDENTIALS);
        
        return httplib::Server::HandlerResponse::Unhandled;
    });

    this->set_logger([&](const httplib::Request &req, const httplib::Response &res) {
        printf("%s", log(req, res).c_str());
    });

    if(!this->listen("0.0.0.0", 8082))
    {
        std::cerr << "Failed to listen\n";
    }

    return 0;
}

int64_t Application::GetTokenValidTime(const std::string& tokenString)
{
    auto bytes = HashToken(tokenString);
    auto result = MakeQuery("SELECT TIMESTAMPDIFF(second, NOW(), validUntil) as validSeconds FROM tokens WHERE hash = ?", bytes);

    if(result && result->rowsCount())
    {
        result->next();
        int64_t seconds = result->getInt64("validSeconds");

        if(seconds > 0)
            return seconds;
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
    auto res = MakeQuery("SELECT C.id as cardID, C.name as cardName, U.name as assignedTo FROM cards as C LEFT JOIN users as U on C.id = U.cardID");

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
    MakeQuery("DELETE FROM users WHERE id=?", id);

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
	                "SET endTime = CURRENT_TIMESTAMP()"
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
