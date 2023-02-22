#pragma once
#include <regex>
#include <string>
#include <optional>
#include <memory>
#include <mariadb/conncpp.hpp>
#include "Clock.h"

inline std::optional<std::string> GetTokenFromString(const std::string& cookies)
{
    std::regex regex("(?:^|;)\\s?token=(.*?)(?:;|$)");
    std::smatch match;
    
    if(!std::regex_search(cookies.begin(), cookies.end(), match, regex))
    {
        return std::nullopt;
    }

    return match[1];
}

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

// Creates and calls a new sql prepared statement, returning a unique_ptr to the result
// Using variadic templates to take a variable amount of arguments here.
template<typename T, typename ... Args>
inline std::unique_ptr<sql::ResultSet> ConnectionMakeQuery(sql::Connection* conn, const std::string& queryString, const T& first, const Args& ... args)
{
    std::unique_ptr<sql::PreparedStatement> query(conn->prepareStatement(queryString));
    AppendToQuery<T, Args...>(query.get(), 1, first, args...);

    return std::unique_ptr<sql::ResultSet>(query->executeQuery());
}

// Creates and calls a new sql prepared statement, returning a unique_ptr to the result
inline std::unique_ptr<sql::ResultSet> ConnectionMakeQuery(sql::Connection* conn, const std::string& queryString)
{
    std::unique_ptr<sql::PreparedStatement> query(conn->prepareStatement(queryString));

    return std::unique_ptr<sql::ResultSet>(query->executeQuery());
}