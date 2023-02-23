#pragma once
#include <mariadb/conncpp.hpp>
#include <iostream>
#include <type_traits>
#include <httplib.h>

#include "json.hpp"
#include "Clock.h"
#include "Util.h"
#include "Housekeeping.h"
using namespace nlohmann;

class Application : httplib::Server
{
public:
    Application();
private:
    // Checks if a request contains a session token, and checks if the token is valid or not.
    inline bool ValidateRequest(const httplib::Request& request, httplib::Response& response, std::string& token, json& data)
    {
        auto rtoken = GetTokenFromString(request.get_header_value("Cookie"));

        if(!rtoken)
        {
            response.status = 401;
            response.body = "{\"error_message\": \"Request does not contain a session token\"}";
            return false;
        }

        try {
            data = json::parse(request.body);
        }
        catch(...) {}

        if(!ValidateToken(*rtoken))
        {
            response.status = 401;
            response.body = "{\"error_message\": \"Authentication failed\"}";

            return false;
        }
        
        token = *rtoken;

        return true;
    }

    [[noreturn]] void HouseKeeping()
    {
        while(true)
        {
            if(addingCard && cardAddingClock.GetTime() > 180)
            {
                addingCard = false;
            }

            Housekeeping::RemoveExpiredTokens(houseKeepingConnection);
            Housekeeping::AutoStopClock(houseKeepingConnection);

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void SetRoutes();

    // Returns how long a token is still valid (in seconds)    
    int64_t GetTokenValidTime(const std::string& tokenString);

    // Checks if a token is valid or not
    bool ValidateToken(const std::string& tokenString);

    // Removes token from the database. This will cause the token user to log out.    
    void RemoveToken(const std::string& token);

    // Adds new token associated with username that is valid for validForSeconds amount of time.
    void AddToken(const std::string& username, const std::string& tokenString, int validSeconds = 1800);

    // Adds a new admin user
    void AddAdmin(const std::string& username, const std::string& password);

    // Authenticates a user using username and password
    bool AuthenticateWithPassword(const std::string& username, const std::string& password);

    // Checks if an admin exists with this name
    bool AdminExists(const std::string& username);

    // Selects all admins info and returns it as json
    json GetAdminsData(std::optional<int> adminID = std::nullopt);

    // Gets the username associated with this token
    std::string GetTokenUser(const std::string& token);

    // Changes password of whoever is using this token
    void ChangeUserPasswordWithToken(const std::string& token, const std::string& newPass);

    // Selects all cards from the database and puts it in a json array
    json GetCardsList();

    // Selects all users (not admin) from the database and puts it in a json array
    // Or if userID has been passed as an argument, just returns the information of the user that matches this id
    json GetUsersData(std::optional<int> userID = std::nullopt);

    // Removes user from the database using database row id
    int RemoveUser(int id);

    // Removes card from the database using database row id
    int RemoveCard(int id);

    int RenameCard(int cardID, const std::string& cardname);
    int PounchCard(int cardID);
    int AddCard(int cardID);

    // Changes user active status to isActive, where isActive is either 0 or 1
    int SetUserActive(int userID, int isActive);

    // Creates and calls a new sql prepared statement, returning a unique_ptr to the result
    // Using variadic templates to take a variable amount of arguments here.
    template<typename T, typename ... Args>
    std::unique_ptr<sql::ResultSet> MakeQuery(const std::string& queryString, const T& first, const Args& ... args)
    {
        std::unique_ptr<sql::PreparedStatement> query(connection->prepareStatement(queryString));
        AppendToQuery<T, Args...>(query.get(), 1, first, args...);

        return std::unique_ptr<sql::ResultSet>(query->executeQuery());
    }
    
    // Creates and calls a new sql prepared statement, returning a unique_ptr to the result
    std::unique_ptr<sql::ResultSet> MakeQuery(const std::string& queryString)
    {
        std::unique_ptr<sql::PreparedStatement> query(connection->prepareStatement(queryString));

        return std::unique_ptr<sql::ResultSet>(query->executeQuery());
    }


    void DeleteUser(const std::string& username)
    {
        MakeQuery("DELETE FROM users WHERE name=?", username);
    }

    bool CardExists(const std::string& cardname)
    {
        return GetCardID(cardname).has_value();
    }

    bool UserExists(const std::string& username)
    {
        const auto result = MakeQuery("SELECT * FROM users WHERE name=? LIMIT 1", username);
        return result->rowsCount() > 0;
    }

    std::optional<int> GetCardID(const std::string& cardname)
    {
        auto res = MakeQuery("SELECT id FROM cards WHERE name = ?", cardname);

        while(res->next())
        {
            return res->getInt("id");
        }

        return std::nullopt;
    }

    void AddUser(const std::string& username, const std::string& cardname)
    {
        MakeQuery("INSERT IGNORE INTO users (name, active) VALUES (?, 1)", username);
    }

    int32_t GetCardUserID(const std::string& cardname)
    {
        auto result = MakeQuery("SELECT U.id FROM users AS U WHERE U.cardID = (SELECT C.id FROM cards AS C WHERE C.name = ?) LIMIT 1", cardname);

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

        auto cardID = GetCardID(cardname);

        MakeQuery("UPDATE users SET cardID = ? WHERE id = ?", *cardID, userID);
    }

private:
    sql::Connection* connection, *houseKeepingConnection;
    sql::Driver* driver;
    Clock cardAddingClock;
    std::thread houseKeepingThread;

    /// Card add mode
    bool addingCard = false;
};