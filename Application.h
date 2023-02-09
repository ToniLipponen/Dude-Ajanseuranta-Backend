/**
 * {
 *      "session-token": "some-random-sequence-of-characters-and-numbers",
 * }
 */

#pragma once
#include <mariadb/conncpp.hpp>
#include <iostream>
#include <type_traits>
#include <httplib.h>

// #define CPPHTTPLIB_OPENSSL_SUPPORT
// #include "httplib.h"
#include "json.hpp"
#include "Clock.h"
using namespace nlohmann;

namespace Impl
{
    inline void AppendToQuery(sql::PreparedStatement* query, int index, int32_t data)
    {
        query->setInt(index, data);
    }

    inline void AppendToQuery(sql::PreparedStatement* query, int index, int64_t data)
    {
        query->setInt64(index, data);
    }

    inline void AppendToQuery(sql::PreparedStatement* query, int index, float data)
    {
        query->setFloat(index, data);
    }

    inline void AppendToQuery(sql::PreparedStatement* query, int index, double data)
    {
        query->setDouble(index, data);
    }

    inline void AppendToQuery(sql::PreparedStatement* query, int index, const std::string& data)
    {
        query->setString(index, data);
    }

    inline void AppendToQuery(sql::PreparedStatement* query, int index, const sql::bytes& data)
    {
        auto nonConst = const_cast<sql::bytes&>(data); // sus
        query->setBytes(index, &nonConst);
    }

    inline void AppendToQuery(sql::PreparedStatement* query, int index) { }
}

template<typename Arg>
inline void AppendToQuery(sql::PreparedStatement* query, int index, const Arg& arg)
{
    Impl::AppendToQuery(query, index, arg);
}

template<typename FirstArg, typename ... Args>
inline void AppendToQuery(sql::PreparedStatement* query, int index, const FirstArg& first, const Args& ... args)
{
    Impl::AppendToQuery(query, index, first);
    AppendToQuery(query, ++index, args...);
}

class Application : httplib::Server
{
public:
    Application() = default;
    virtual ~Application() = default;
    int Run();

private:
    inline bool ValidateRequest(const httplib::Request& request, httplib::Response& response, json& data)
    {
        std::string token;

        try {
            data = json::parse(request.body);
        }
        catch(std::exception e)
        {
            std::cout << "Request body does not contain valid json\n";
            response.status = 400;
            response.body = "{\"error_message\": \"Request body does not contain valid json\"}";
            return false;
        }

        if(data.find("token") == data.end())
        {
            std::cout << "Request does not contain a session token\n";
            response.status = 400;
            response.body = "{\"error_message\": \"Request does not contain a session token\"}";
            return false;
        }
        
        token = data.at("token");

        if(!ValidateToken(token))
        {
            std::cout << "Authentication failed\n";
            response.status = 401;
            response.body = "{\"error_message\": \"Authentication failed\"}";

            return false;
        }

        return true;
    }

    void HouseKeeping()
    {
        while(1)
        {
            if(addingCard && cardAddingClock.GetTime() > 300)
            {
                addingCard = false;
            }

            MakeQuery(houseKeepingConnection, "DELETE FROM tokens WHERE validUntil < NOW()");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    int64_t GetTokenValidTime(const std::string& tokenString);
    bool ValidateToken(const std::string& tokenString);
    bool AuthenticateWithToken(const std::string& tokenString);
    void RemoveToken(const std::string& token);
    void AddToken(const std::string& username, const std::string& tokenString, int validForDays = 1);
    void AddAdmin(const std::string& username, const std::string& password);
    bool AuthenticateWithPassword(const std::string& username, const std::string& password);
    bool AdminExists(const std::string& username);
    std::string GetTokenUser(const std::string& token);
    void ChangeUserPasswordWithToken(const std::string& token, const std::string& newPass);
    json GetCardsList();
    json GetUsersData();
    int RemoveUser(int id);
    int RemoveCard(int id);
    int RenameCard(int cardID, const std::string& cardname);
    int PounchCard(int cardID);
    int AddCard(int cardID);
    int SetUserActive(int userID, int isActive);

    template<typename T, typename ... Args>
    std::unique_ptr<sql::ResultSet> MakeQuery(const std::string& queryString, const T& first, const Args& ... args)
    {
        std::unique_ptr<sql::PreparedStatement> query(connection->prepareStatement(queryString));
        AppendToQuery<T, Args...>(query.get(), 1, first, args...);

        return std::unique_ptr<sql::ResultSet>(query->executeQuery());
    }
    
    std::unique_ptr<sql::ResultSet> MakeQuery(const std::string& queryString)
    {
        std::unique_ptr<sql::PreparedStatement> query(connection->prepareStatement(queryString));

        return std::unique_ptr<sql::ResultSet>(query->executeQuery());
    }

    template<typename T, typename ... Args>
    std::unique_ptr<sql::ResultSet> MakeQuery(sql::Connection* conn, const std::string& queryString, const T& first, const Args& ... args)
    {
        std::unique_ptr<sql::PreparedStatement> query(conn->prepareStatement(queryString));
        AppendToQuery<T, Args...>(query.get(), 1, first, args...);

        return std::unique_ptr<sql::ResultSet>(query->executeQuery());
    }
    
    std::unique_ptr<sql::ResultSet> MakeQuery(sql::Connection* conn, const std::string& queryString)
    {
        std::unique_ptr<sql::PreparedStatement> query(conn->prepareStatement(queryString));

        return std::unique_ptr<sql::ResultSet>(query->executeQuery());
    }

    void DeleteUser(const std::string& username)
    {
        MakeQuery("DELETE FROM users WHERE name=?", username);
    }

    bool CardExists(const std::string& cardname)
    {
        const auto result = MakeQuery("SELECT * FROM cards WHERE name=? LIMIT 1", cardname);

        return result->rowsCount() > 0;
    }

    bool UserExists(const std::string& username)
    {
        const auto result = MakeQuery("SELECT * FROM users WHERE name=? LIMIT 1", username);
        return result->rowsCount() > 0;
    }

    void AddUser(const std::string& username, const std::string& cardname)
    {
        if(!cardname.empty() && !CardExists(cardname))
        {
            throw std::runtime_error("Card doesn't exist");
        }

        MakeQuery("INSERT INTO users (name, cardName, active) VALUES (?, ?, 1)", username, cardname);
    }

    int32_t GetCardUserID(const std::string& cardname)
    {
        auto result = MakeQuery("SELECT id FROM users WHERE cardName=? LIMIT 1", cardname);

        if(result && result->rowsCount())
        {
            result->next();

            return result->getInt("id");
        }

        return 0;
    }

    void UpdateUser(int userID, const std::string& cardname)
    {
        if(!cardname.empty() && !CardExists(cardname))
        {
            throw std::runtime_error("Card doesn't exist");
        }

        int32_t previousUserID = GetCardUserID(cardname);

        if(!cardname.empty() && previousUserID)
        {
            UpdateUser(previousUserID, "");
        }

        MakeQuery("UPDATE users SET cardName = ? WHERE id = ?", cardname, userID);
    }

private:
    sql::Connection* connection, *houseKeepingConnection;
    sql::Driver* driver;
    Clock cardAddingClock;
    std::thread houseKeepingThread;

    /// Card add mode
    bool addingCard = false;
};