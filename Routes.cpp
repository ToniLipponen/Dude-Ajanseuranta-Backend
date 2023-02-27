#include "Application.h"
#include "Config.h"
#include "Crypt.h"
#include <csv.hpp>

void Application::SetRoutes()
{
    this->Get("/api/v1/user/times/(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        std::string token;
        json data;

        if(!ValidateRequest(request, response, token, data))
            return;

        if(ValidateToken(token))
        {
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
            response.status = Http::Unauthorized;
            return;
        }
    });

    /// Pounch in/out
    // TODO: Respond pounch in / pounch out with different message.
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
            response.status = 419; // Invalid json in request body
            response.body = json({{"error_message", "Failed to parse json"}}).dump();
            return;
        }

        if(addingCard)
        {
            if(AddCard(uid) != 0)
            {
                response.status = 420; // Tried to add card that already exists in the system
                response.body = json({{"error_message", "Card already exists"}}).dump();
                return;
            }
        }
        else
        {
            if(PounchCard(uid) != 0)
            {
                response.status = 421; // Tried to pounch in with a card that has not been added to the system yet
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
        auto 🍪  = "Cookie";
        auto token = GetTokenFromString(request.get_header_value(🍪));

        if(!token)
        {
            // No token in cookie. Not an issue though, since we are loggin out.
            response.status = Http::Bad_Request; 
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
        }
        catch(...) {
            response.status = Http::Bad_Request;
            response.body = "{\"error_message\": \"Failed to parse request body.\"}";
            return;
        }

        try {
            username = data.at("username");
            password = data.at("password");
            remember = data.at("remember");
        }
        catch(...) {
            // One of the above fields is missing from the request body.
            response.status = Http::Bad_Request;
            response.body = "{\"error_message\": \"Request body did not contain valid json data.\"}";
            return;
        }

        if(!AuthenticateWithPassword(username, password))
        {
            // Either password or or username is incorrect.
            // Or this user doesn't exist
            response.status = Http::Forbidden;
            response.body = "{\"error_message\": \"Access denied\"}";
            return;
        }

        auto token = GenerateToken();
        AddToken(username, token, (remember ? 604800 : 30));
        response.set_header("Set-Cookie", "token=" + token + " ;SameSite=None;" FRONTEND_SECURE_POLICY);
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
            response.status = Http::Bad_Request;
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
            response.status = Http::Bad_Request;
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
            // One of the above fields are missing
            response.status = Http::Bad_Request;
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

        response.body = result.empty() ? "{}" : result.dump();
    });

    this->Get("/api/v1/user/get/(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        std::string userIDString;
        
        try
        {
            userIDString = request.matches[1];
            
            if(userIDString.empty())
            {
                throw std::runtime_error("No user id in path");
            }
        }
        catch(...)
        {
            response.status = Http::Bad_Request;
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

        std::string adminIDString;
        try 
        {
            adminIDString = request.matches[1];
            
            if(adminIDString.empty())
            {
                throw std::runtime_error("No admin id in path");
            }
        }
        catch(...)
        {
            response.status = Http::Bad_Request;
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
            response.status = Http::Bad_Request;
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
            response.status = Http::Bad_Request;
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

    this->Options("(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        response.set_header("Access-Control-Allow-Headers", headers.at("Access-Control-Allow-Origin"));
    });
}