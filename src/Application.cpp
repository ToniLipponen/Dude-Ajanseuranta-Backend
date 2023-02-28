#include "include/Application.h"
#include "include/Util.h"
#include "include/Logging.h"

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

    AddAdmin("admin", "admin");
    houseKeepingThread = std::thread([&](){ HouseKeeping();});
    houseKeepingThread.detach();

    SetRoutes();

#ifndef NO_LOGGING
    this->set_logger([&](const httplib::Request &req, const httplib::Response &res) {
        printf("%s", log(req, res).c_str());
    });
#endif

    std::cout << "Server started" << std::endl;

    if(!this->listen("0.0.0.0", 8082))
    {
        throw std::runtime_error("Server failed to listen");
    }
}

// Checks if a request contains a session token, and checks if the token is valid or not.
bool Application::ValidateRequest(const httplib::Request& request, httplib::Response& response, std::string& token, json& data)
{
    auto _token = GetTokenFromString(request.get_header_value("Cookie"));

    if(!_token)
    {
        response.status = Http::Unauthorized;
        response.body = R"({"error_message": "Request does not contain a session token"})";
        return false;
    }

    try {
        data = json::parse(request.body);
    }
    catch(...){}

    if(!ValidateToken(*_token))
    {
        response.status = Http::Unauthorized;
        response.body = R"({"error_message": "Authentication failed"})";

        return false;
    }

    token = *_token;

    return true;
}

bool Application::ValidateRequest(const httplib::Request& request, httplib::Response& response)
{
    json data;
    std::string token;
    return ValidateRequest(request, response, token, data);
}

bool Application::ValidateRequest(const httplib::Request& request, httplib::Response& response, std::string& token)
{
    json data;
    return ValidateRequest(request, response, token, data);
}

bool Application::ValidateRequest(const httplib::Request& request, httplib::Response& response, json& data)
{
    std::string token;
    return ValidateRequest(request, response, token, data);
}

[[noreturn]]
void Application::HouseKeeping()
{
    while(true)
    {
        if(addingCard && cardAddingClock.GetTime() > 180)
        {
            addingCard = false;
        }

        Housekeeping::RemoveExpiredTokens(houseKeepingConnection);
        Housekeeping::AutoStopClock(houseKeepingConnection);
        Housekeeping::KeepConnectionAlive(houseKeepingConnection);
        Housekeeping::KeepConnectionAlive(connection);

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}
