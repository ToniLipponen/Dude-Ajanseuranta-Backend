#include "Housekeeping.h"
#include <chrono>

void Housekeeping::RemoveExpiredTokens(sql::Connection* connection)
{
    ConnectionMakeQuery(connection, "DELETE FROM tokens WHERE validUntil < NOW()");
}

void Housekeeping::KeepConnectionAlive(sql::Connection* connection)
{
    ConnectionMakeQuery(connection, "SELECT 1");
}

void Housekeeping::AutoStopClock(sql::Connection* connection)
{
    static int previousDay = -1;

    const std::time_t now = std::time(nullptr); 
    std::tm time = *std::gmtime(&now);
    time.tm_hour += 2;

    if(time.tm_mday != previousDay && time.tm_hour >= 18)
    {
        previousDay = time.tm_mday;
        ConnectionMakeQuery(connection,
            "UPDATE times " 
            "SET endTime = CONCAT(DATE(beginTime), ' 15:00'), forgotLogout = 1 "
            "WHERE endTime IS NULL");

        ConnectionMakeQuery(connection, "UPDATE users SET present = 0");
    }
}