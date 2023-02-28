#include "Application.h"

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

    if(!saltResult->next())
    {
        return false;
    }

    std::string salt = saltResult->getString("salt").c_str();

    auto passwordHash = HashPassword(password, salt);
    auto idResult = MakeQuery("SELECT id "
                              " FROM admins WHERE name=? AND passwd=?", username, passwordHash);

    return (idResult && idResult->rowsCount() > 0);
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
        res = MakeQuery("SELECT * FROM admins");
    }

    json data = json::array();

    while(res->next())
    {
        int32_t id          = res->getInt("id");
        std::string name    = res->getString("name").c_str();

        data.push_back({
            {"id",  id},
            {"name",name}
        });
    }

    return data;
}
