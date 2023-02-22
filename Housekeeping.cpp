#include "Housekeeping.h"
#include <chrono>

void Housekeeping::RemoveExpiredTokens(sql::Connection* connection)
{
    ConnectionMakeQuery(connection, "DELETE FROM tokens WHERE validUntil < NOW()");
}

void Housekeeping::AutoStopClock(sql::Connection* connection)
{
    static int previousDay = -1;

    const std::time_t now = std::time(nullptr); // get the current time point
    const std::tm time = *std::localtime(&now);

    if(time.tm_mday != previousDay && time.tm_hour >= 18)
    {
        previousDay = time.tm_mday;
        ConnectionMakeQuery(connection,
            "UPDATE times " 
            "SET endTime = CONCAT(CURDATE(), ' 15:00'), forgotLogout = 1 "
            "WHERE endTime IS NULL");

        ConnectionMakeQuery(connection, "UPDATE users SET present = 0");
    }
}