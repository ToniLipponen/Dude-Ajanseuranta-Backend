#pragma once
#include <mariadb/conncpp.hpp>
#include <iostream>
#include <type_traits>

#include "httplib.h"
#include "json.hpp"
#include "Clock.h"
#include "Util.h"
#include "Housekeeping.h"
#include "Config.h"
#include "Crypt.h"

using namespace nlohmann; //!< json library namespace

class Application : httplib::Server
{
public:
    Application();
private:
    // Checks if a request contains a session token, and checks if the token is valid or not.
    bool ValidateRequest(
            const httplib::Request& request,
            httplib::Response& response,
            std::string& token,
            json& data);

    bool ValidateRequest(const httplib::Request& request, httplib::Response& response);
    bool ValidateRequest(const httplib::Request& request, httplib::Response& response, std::string& token);
    bool ValidateRequest(const httplib::Request& request, httplib::Response& response, json& data);

    [[noreturn]]
    void HouseKeeping();

    void SetRoutes();

    /// Creates and calls a new sql prepared statement, returning a unique_ptr to the result
    /// Using variadic templates to take a variable amount of arguments here.
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

    /////////////////////////////////////////////////////////
    ///// Token releated functions. Definition in src/Token.cpp
    /////////////////////////////////////////////////////////

    /// Returns how long a token is still valid (in seconds)
    int64_t GetTokenValidTime(const std::string& tokenString);

    /// Checks if a token is valid or not
    bool ValidateToken(const std::string& tokenString);

    /// Removes token from the database. This will cause the token user to log out.
    void RemoveToken(const std::string& token);

    /// Adds new token associated with username that is valid for validForSeconds amount of time.
    void AddToken(const std::string& username, const std::string& tokenString, int validSeconds = 1800);

    /// Gets the username associated with this token
    std::string GetTokenUser(const std::string& token);


    /////////////////////////////////////////////////////////
    ///// Admin releated functions. Definition in src/Admin.cpp
    /////////////////////////////////////////////////////////

    /// Adds a new admin user
    void AddAdmin(const std::string& username, const std::string& password);

    /// Authenticates a user using username and password
    bool AuthenticateWithPassword(const std::string& username, const std::string& password);

    /// Checks if an admin exists with this name
    bool AdminExists(const std::string& username);

    /// Selects all admins info and returns it as json
    json GetAdminsData(std::optional<int> adminID = std::nullopt);

    /////////////////////////////////////////////////////////
    ///// User releated functions. Definition in src/User.cpp
    /////////////////////////////////////////////////////////

    /// Changes password of whoever is using this token
    void ChangeUserPasswordWithToken(const std::string& token, const std::string& newPass);

    /// Removes user from the database using username
    void DeleteUser(const std::string& username);

    /// Removes user from the database using database row id
    void DeleteUser(int id);

    bool UserExists(const std::string& username);

    /// Adds new user, duh
    void AddUser(const std::string& username);

    /// Sets users card, or if cardname is empty users card is set to null
    void UpdateUser(int userID, const std::string& cardname);

    /// Selects all users (not admin) from the database and puts it in a json array
    /// Or if userID has been passed as an argument, just returns the information of the user that matches this id
    json GetUsersData(std::optional<int> userID = std::nullopt);


    /////////////////////////////////////////////////////////
    ///// Card releated functions. Definition in src/Card.cpp
    /////////////////////////////////////////////////////////

    /// Selects all cards from the database and puts it in a json array
    json GetCardsList();

    /// Removes card from the database using database row id
    int RemoveCard(int id);
    int RenameCard(int cardID, const std::string& cardname);
    int PounchCard(int cardID);
    int AddCard(int cardID);
    int32_t GetCardUserID(const std::string& cardname);
    int32_t GetCardID(const std::string& cardname);
    bool CardExists(const std::string& cardname);

private:
    sql::Connection* connection, *houseKeepingConnection;
    sql::Driver* driver;
    Clock cardAddingClock;
    std::thread houseKeepingThread;
    std::mutex mutex;
    bool addingCard = false;
};