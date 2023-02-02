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
    //// Hashing
    // const unsigned char data[] = "data to hash";
    // unsigned char hash[SHA512_DIGEST_LENGTH];
    // SHA512(data, sizeof(data) - 1, hash);
    // std::cout << data << " " << hash << std::endl;

    //// Json parsing
    // json data = json::parse(R"({"name": "somename", "cardID": 1234})");
    // auto name = data.at("name");
    // std::cout << name << std::endl;

    // Get driver instance 
    driver = sql::mariadb::get_driver_instance();

    if(!driver)
    {
        std::cerr << "Failed to get sql driver instance\n";
        return 1;
    }

    // Make connection to the database
    // TODO: Take properties from ENV
    sql::SQLString url("jdbc:mariadb://localhost:3306/mydb");
    sql::Properties properties({{"user", "toni"}, {"password", "toni"}});

    connection = driver->connect(url, properties);

    if(!connection)
    {
        std::cerr << "Failed to connect to database\n";
        return 2;
    }

    this->Get("/times", [&](const httplib::Request& request, httplib::Response& response)
    {
        std::string token;
        json data;

        // try 
        // {
        //     data = json::parse(request.body);
        // }
        // catch(std::exception e)
        // {
        //     response.status = 400;
        //     return;
        // };

        // token = data.at("session-token");

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
        json data = json::parse(request.body);
        std::string cardName = data.at("cardName");
        int uid = data.at("uid");
        
        if(MakeQuery("SELECT * FROM cards WHERE cardName=?", cardName)->rowsCount() > 0)
        {
            MakeQuery<std::string, int>("INSERT INTO cards (cardName, cardID) VALUES (?, ?)", cardName, uid);

            PrintResult(MakeQuery("SELECT * FROM cards").get());
            response.status = 200;
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
            response.status = 403;
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
        json data;
        std::string username, password;
        bool remember = 0;
        response.set_header("Access-Control-Allow-Origin", "*");

        if(!ValidateRequest(request, response, data))
        {
            return;
        }

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
        AddToken(username, token, (remember ? 30 : 1));
        response.body = json({{"token", token}}).dump();
    });

    std::cout << "Connected to database" << std::endl;

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
    auto result = MakeQuery("SELECT TIMESTAMPDIFF(second, validUntil, NOW()) as validSeconds WHERE hash = ?", bytes);

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
    auto idResult = MakeQuery("SELECT id FROM admins WHERE name = ?", user);
    
    if(!idResult || idResult->rowsCount() == 0)
    {
        throw std::runtime_error("Invalid user");
    }

    idResult->next();

    auto id = idResult->getInt("id");
    auto tokenHash = HashToken(token);

    MakeQuery("INSERT INTO tokens (adminId, hash, validUntil) " 
        "VALUES (?,?,TIMESTAMPADD(second, ?, NOW()))", id, tokenHash, validSeconds);
}

void Application::AddAdmin(const std::string& username, const std::string& password)
{
    auto salt = GenerateToken();
    auto passwordHash = HashPassword(password, salt);

    // Todo make sure there are no duplicate users
    MakeQuery("INSERT INTO admins (name, passwd, salt) VALUES (?, ?, ?)", username, passwordHash, salt);
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