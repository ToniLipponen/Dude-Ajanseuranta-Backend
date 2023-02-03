#include "Application.h"
#include "Crypt.h"
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
            "cardName VARCHAR(64), "
            "active INT, PRIMARY KEY(id))");

    MakeQuery("CREATE TABLE IF NOT EXISTS cards ("
            "id INT NOT NULL AUTO_INCREMENT, "
            "name VARCHAR(64), "
            "cardID INT, PRIMARY KEY(id))");

    MakeQuery("CREATE TABLE IF NOT EXISTS times ("
            "id INT NOT NULL AUTO_INCREMENT, "
            "userID INT, "
            "beginTime TIMESTAMP, "
            "endTime TIMESTAMP, "
            "cardID INT, PRIMARY KEY(id))");

    MakeQuery("CREATE TABLE IF NOT EXISTS tokens ("
            "adminName VARCHAR(64),"
            "hash BINARY(64), "
            "validUntil TIMESTAMP)");

    this->Get("/times", [&](const httplib::Request& request, httplib::Response& response)
    {
        std::string token;
        json data;

        try 
        {
            data = json::parse(request.body);
        }
        catch(std::exception e)
        {
            response.status = 400;
            return;
        }

        if(ValidateToken(token))
        {   
            response.set_header("Access-Control-Allow-Origin", "*");

            response.set_content(
                R"(
                {
                    "some-field": "some-value"
                })",
                "application/json"
            );

            response.status = 200;
        }
        else
        {
            response.status = 401; /// Unauthorized
        }
    });

    this->Post("/add", [&](const httplib::Request& request, httplib::Response& response)
    {
        if(addingCard)
        {
            json data = json::parse(request.body);
            std::string cardName = "DUDE" + std::to_string(Math::Random(1, 9999));
            int uid = data.at("uid");
            
            if(MakeQuery("SELECT * FROM cards WHERE name=?", cardName)->rowsCount() <= 0)
            {
                MakeQuery<std::string, int>("INSERT INTO cards (name, cardID) VALUES (?, ?)", cardName, uid);

                PrintResult(MakeQuery("SELECT * FROM cards").get());
            }
            else
            {
                response.status = 420;
                return;
            }
        }
    });

    /// Pounch in/out 
    this->Post("/test", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data = json::parse(request.body);
        int uid = data.at("uid");

        if(MakeQuery("SELECT * FROM cards WHERE cardID=?", uid)->rowsCount() == 0)
        {
            response.status = 420;
            return;
        }
        else
        {
            response.status = 200; // OK
        }
    });

    this->Post("/validate", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;
        response.set_header("Access-Control-Allow-Origin", "*");

        try
        {
            data = json::parse(request.body);

            token = data.at("token");
        }
        catch(std::exception e)
        {
            response.status = 400;
            return;
        }

        if(!ValidateToken(token))
        {
            response.status = 401;
            return;
        }

        auto seconds = GetTokenValidTime(token);
        json responseData({"validSeconds", seconds});

        response.body = responseData.dump();
    });

    this->Post("/logout", [&](const httplib::Request& request, httplib::Response& response)
    {
        /// This might throw, but I don't care. 
        /// Httplib is going to catch it and log it anyway.
        /// This is not an issue.
        response.set_header("Access-Control-Allow-Origin", "*");

        json data = json::parse(request.body);

        std::string token = data.at("token");
        RemoveToken(token);
    });

    this->Post("/login", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string username, password;
        bool remember = 0;
        response.set_header("Access-Control-Allow-Origin", "*");

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
        response.body = json({{"token", token}}).dump();
    });

    this->Post("/changepassword", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        
        if(!ValidateRequest(request, response, data))
        {
            return;
        }

        if(data.find("newpass") == data.end())
        {
            response.status = 400; // Bad request
            return;
        }

        std::string newPassword = data.at("newpass");
        std::string token = data.at("token");

        try
        {
            ChangeUserPasswordWithToken(token, newPassword);
        }
        catch(std::exception& e)
        {
            response.status = 500;
            response.body = json({{"error_message", e.what()}}).dump();
            return;
        }
    });

    this->Post("/getcardlist", [&](const httplib::Request& request, httplib::Response& response)
    {
        response.set_header("Access-Control-Allow-Origin", "*");
        json data;
        
        if(!ValidateRequest(request, response, data))
        {
            return;
        }

        auto cards = GetCardsList();

        response.body = cards.dump();
    });

    this->Post("/setcardreadingmode", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;

        if(!ValidateRequest(request, response, data))
        {
            return;
        }

        int state = 0;

        try
        {
            state = data.at("state");
        }
        catch(std::exception& e)
        {
            response.body = json({{"error_message", e.what()}});
            response.status = 400;
            return;
        }

        addingCard = state > 0;

        if(addingCard)
        {
            cardAddingClock.Reset();
        }
    });

    this->Post("/user/add", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;

        if(!ValidateRequest(request, response, data))
        {
            return;
        }

        std::string username, cardname;

        try
        {
            username = data.at("username");
            cardname = data.at("cardname");
        }
        catch(std::exception& e)
        {
            response.status = 400;
            response.body = json({{"error_message", e.what()}}).dump();
            return;
        }

        AddUser(username, cardname);
    });

    std::cout << "Connected to database" << std::endl;

    AddAdmin("admin", "admin");
    houseKeepingThread = std::thread([&](){ HouseKeeping();});
    houseKeepingThread.detach();

    this->set_logger([&](const httplib::Request &req, const httplib::Response &res) {
        printf("%s", log(req, res).c_str());
    });

    if(!this->listen("0.0.0.0", 8081))
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
    MakeQuery("UPDATE admins SET passwd = ?, salt = ? WHERE name = ?", passwdHash, newSalt, username);
}

json Application::GetCardsList()
{
    auto res = MakeQuery("SELECT C.id as cardID, C.name as cardName, U.name as assignedTo FROM cards as C LEFT JOIN users as U on U.active = 1");

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

    // std::cout << data.dump() << std::endl;

    return data;
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
