#include "Application.h"

json Application::GetCardsList()
{
    auto res = MakeQuery("SELECT C.id as cardID, C.name as cardName, U.name as assignedTo "
                         "FROM cards as C LEFT JOIN users as U on C.id = U.cardID");

    if(!res || res->rowsCount() == 0)
    {
        return {};
    }

    json data = json::array();

    while(res->next())
    {
        std::string cardname    = res->getString("cardName").c_str();
        int32_t cardid          = res->getInt("cardID");
        std::string assignedTo  = res->getString("assignedTo").c_str();

        data.push_back({
            {"cardname",    cardname},
            {"cardid",      cardid},
            {"assingedto",  assignedTo}
        });
    }

    return data;
}

int Application::RemoveCard(int id)
{
    MakeQuery("DELETE FROM cards WHERE id=?", id);

    return 0;
}

int Application::RenameCard(int cardID, const std::string& cardname)
{
    MakeQuery("UPDATE cards SET name = ? WHERE id = ?", cardname, cardID);

    return 0;
}

int Application::PounchCard(int cardID)
{
    auto result = MakeQuery("SELECT id FROM cards WHERE cardID=?", cardID);

    if(result->rowsCount())
    {
        result->next();
        cardID = result->getInt("id");
        auto idResult = MakeQuery("SELECT id FROM users WHERE cardID=?", cardID);

        if(!idResult || idResult->rowsCount() == 0)
        {
            std::cout << "This card has not been assigned to anyone\n";
            return 2;
        }

        idResult->next();
        int id = idResult->getInt("id");

        if(MakeQuery("SELECT * FROM times WHERE endTime IS NULL AND userID = ?", id)->rowsCount())
        {
            MakeQuery("UPDATE times "
                      "SET endTime = CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+02:00') "
                      "WHERE endTime IS null AND userID = ?;", id);
        }
        else
        {
            MakeQuery("INSERT INTO times (userID) values(?)", id);
        }

        MakeQuery("UPDATE users SET present = !present WHERE id = ?", id);
        return 0;
    }

    return 1;
}

int Application::AddCard(int cardID)
{
    /// Check if card already exists
    if(MakeQuery("SELECT * FROM cards WHERE cardID=?", cardID)->rowsCount() != 0)
    {
        /// If exists return 1
        return 1;
    }

    /// Add the card into cards
    MakeQuery("INSERT INTO cards (name, cardID) VALUES (?, ?)", "Unnamed card" + std::to_string(cardID), cardID);

    return 0;
}

int32_t Application::GetCardUserID(const std::string& cardname)
{
    auto result = MakeQuery("SELECT U.id FROM users AS U WHERE U.cardID = (SELECT C.id FROM cards AS C WHERE C.name = ?) LIMIT 1", cardname);

    if(result->next())
    {
        return result->getInt("id");
    }

    return -1;
}

int32_t Application::GetCardID(const std::string& cardname)
{
    auto result = MakeQuery("SELECT id FROM cards WHERE name = ?", cardname);

    if(result->next())
    {
        return result->getInt("id");
    }

    return -1;
}

bool Application::CardExists(const std::string& cardname)
{
    return GetCardID(cardname) >= 0;
}