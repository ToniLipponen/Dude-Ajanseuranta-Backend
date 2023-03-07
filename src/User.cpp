#include "Application.h"

void Application::ChangeUserPasswordWithToken(const std::string& token, const std::string& newPass)
{
    auto username = GetTokenUser(token);
    auto newSalt = GenerateToken();
    auto passwdHash = HashPassword(newPass, newSalt);

    MakeQuery("DELETE FROM tokens WHERE adminName=?", username);
    MakeQuery("UPDATE admins SET passwd = ?, salt = ? WHERE name = ?", passwdHash, newSalt, username);
}

void Application::DeleteUser(const std::string& username)
{
    MakeQuery("DELETE FROM times WHERE userID = (SELECT id FROM users WHERE name = ?)", username);
    MakeQuery("DELETE FROM users WHERE name=?", username);
}

void Application::DeleteUser(int id)
{
    MakeQuery("DELETE FROM times WHERE userID = ?", id);
    MakeQuery("DELETE FROM users WHERE id = ?", id);
}

bool Application::UserExists(const std::string& username)
{
    const auto result = MakeQuery("SELECT * FROM users WHERE name=? LIMIT 1", username);
    return result->rowsCount() > 0;
}

void Application::AddUser(const std::string& username)
{
    MakeQuery("INSERT IGNORE INTO users (name, active) VALUES (?, 1)", username);
}

void Application::UpdateUser(int userID, const std::string& cardname)
{
    int32_t cardID = GetCardID(cardname);

    if(cardID >= 0)
    {
        int32_t previousUserID = GetCardUserID(cardname);

        if(previousUserID >= 0)
        {
            MakeQuery("UPDATE users SET cardID = null WHERE id = ?", previousUserID);
        }

        MakeQuery("UPDATE users SET cardID = ? WHERE id = ?", cardID, userID);
    }
    else
    {
        MakeQuery("UPDATE users SET cardID = null WHERE id = ?", userID);
    }
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
