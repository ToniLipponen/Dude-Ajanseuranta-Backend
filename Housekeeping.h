#pragma once
#include "Util.h"

namespace Housekeeping
{
    void RemoveExpiredTokens(sql::Connection* connection);
    void AutoStopClock(sql::Connection* connection);
}