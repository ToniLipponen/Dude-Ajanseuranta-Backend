#include "Application.h"

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
