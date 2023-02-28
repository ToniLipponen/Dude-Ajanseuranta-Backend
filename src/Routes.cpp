#include "include/Application.h"
#include "include/Config.h"
#include "include/Crypt.h"

void Application::SetRoutes()
{
    this->Get("/api/v1/user/times/(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        if(!ValidateRequest(request, response))
            return;

        if(request.matches.empty())
        {
            response.status = Http::Bad_Request;
            response.body = json({{"error_message", "No user id in path"}}).dump();
            return;
        }

        std::string userIDString = request.matches[1];
        int userID = std::stoi(userIDString);

        //// Maybe put this in a separate function
        ////--------------------------------------------------

        auto res = MakeQuery("SELECT "
                             "UNIX_TIMESTAMP(beginTime) as ubeginTime, "
                             "UNIX_TIMESTAMP(endTime) as uendTime "
                             "FROM  times WHERE userID = ? "
                             "ORDER BY beginTime DESC", userID);

        json data = json::array();

        while(res->next())
        {
            int beginTime = res->getInt("ubeginTime");
            int endTime = res->getInt("uendTime");

            data.push_back({{"begin_time", beginTime}, {"end_time", endTime}});
        }
        ////--------------------------------------------------

        response.body = data.dump();
    });

    /// Pounch in/out
    /// TODO: Respond pounch in / pounch out with different message.
    this->Post("/api/v1/card/read", [&](const httplib::Request& request, httplib::Response& response)
    {
        int uid;

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
        std::string token;

        if(!ValidateRequest(request, response, token))
        {
            return;
        }

        auto seconds = GetTokenValidTime(token);
        json responseData({"validSeconds", seconds});

        response.body = responseData.dump();
    });

    this->Post("/api/v1/logout", [&](const httplib::Request& request, httplib::Response& response)
    {
        auto token = GetTokenFromString(request.get_header_value("Cookie"));

        if(!token)
        {
            // No token in cookie. Not an issue though, since we are logging out.
            response.status = Http::Bad_Request; 
            return;
        }

        RemoveToken(*token);
    });

    this->Post("/api/v1/login", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string username, password;
        bool remember;

        try {
            data = json::parse(request.body);
            username = data.at("username");
            password = data.at("password");
            remember = data.at("remember");
        }
        catch(...) {
            response.status = Http::Bad_Request;
            response.body = R"({"error_message": "Failed to parse request body."})";
            return;
        }

        if(!AuthenticateWithPassword(username, password))
        {
            // Either password or username is incorrect.
            // Or this user doesn't exist
            response.status = Http::Forbidden;
            response.body = R"({"error_message": "Access denied"})";
            return;
        }

        auto token = GenerateToken();
        AddToken(username, token, (remember ? 604800 : 3600));
        response.set_header("Set-Cookie", "token=" + token + " ;SameSite=None;" FRONTEND_SECURE_POLICY);
    });

    this->Post("/api/v1/changepassword", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string token, newPass;

        if(!ValidateRequest(request, response, token, data))
        {
            return;
        }

        try
        {
            newPass = data.at("newpass");
        }
        catch(std::exception& e)
        {
            response.status = Http::Bad_Request;
            response.body = json({{"error_message", e.what()}}).dump();
            return;
        }

        ChangeUserPasswordWithToken(token, newPass);
    });

    this->Get("/api/v1/card/get", [&](const httplib::Request& request, httplib::Response& response)
    {
        if(!ValidateRequest(request, response))
        {
            return;
        }

        auto cards = GetCardsList();

        response.body = cards.dump();
    });

    this->Post("/api/v1/card/readingmode/(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        const std::string state = request.matches[1];

        if(!ValidateRequest(request, response))
        {
            return;
        }

        addingCard = (state == "start");

        if(addingCard)
        {
            cardAddingClock.Reset();
        }
    });

    this->Post("/api/v1/user/add", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;
        std::string username;

        if(!ValidateRequest(request, response, data))
        {
            return;
        }

        try
        {
            username = data.at("username");
        }
        catch(std::exception& e)
        {
            response.status = Http::Bad_Request;
            response.body = json({{"error_message", e.what()}}).dump();
            return;
        }

        AddUser(username);
    });

    this->Post("/api/v1/user/updatecard", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;

        if(!ValidateRequest(request, response, data))
        {
            return;
        }

        std::string cardname;
        int userID;

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
        if(!ValidateRequest(request, response))
        {
            return;
        }

        auto result = GetUsersData();

        response.body = result.empty() ? "{}" : result.dump();
    });

    this->Get("/api/v1/user/get/(\\d+)", [&](const httplib::Request& request, httplib::Response& response)
    {
        if(!ValidateRequest(request, response))
        {
            return;
        }

        if(request.matches.empty())
        {
            response.status = Http::Bad_Request;
            response.body = json({{"error_message", "No user id in path"}}).dump();
            return;
        }

        std::string userIDString = request.matches[1];

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
        if(!ValidateRequest(request, response))
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

    this->Get("/api/v1/admin/get/(\\d+)", [&](const httplib::Request& request, httplib::Response& response)
    {
        if(!ValidateRequest(request, response))
        {
            return;
        }

        if(request.matches.empty())
        {
            response.status = Http::Bad_Request;
            response.body = json({{"error_message", "No admin id in path"}}).dump();
            return;
        }

        std::string adminIDString = request.matches[1];

        auto result = GetAdminsData(std::stoi(adminIDString));

        if(result.empty())
        {
            response.body = "{}";
        }
        else
        {
            response.body = result.dump();
        }
    });

    this->Post("/api/v1/admin/add", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;

        if(!ValidateRequest(request, response, data))
        {
            return;
        }

        // TODO: Put these in a try catch block, and return a specific error if fails
        std::string username;
        std::string password;

        try
        {
            username = data.at("username");
            password = data.at("password");
        }
        catch(const std::exception& e)
        {
            response.status = Http::Bad_Request;
            response.body = json({{"error_message", e.what()}});
            return;
        }

        AddAdmin(username, password);
    });

    this->Post("/api/v1/user/remove", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;

        if(!ValidateRequest(request, response, data))
        {
            return;
        }

        int id = data.at("id");

        DeleteUser(id);
    });

    this->Post("/api/v1/card/remove", [&](const httplib::Request& request, httplib::Response& response)
    {
        json data;

        if(!ValidateRequest(request, response, data))
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
        json data;

        if(!ValidateRequest(request, response, data))
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

    this->Options("(.*?)", [&](const httplib::Request& request, httplib::Response& response)
    {
        response.set_header("Access-Control-Allow-Headers", headers.at("Access-Control-Allow-Origin"));
    });

    this->set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res)
    {
        for(const auto& header : headers)
        {
          res.set_header(header.first, header.second);
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });
}