#include <openssl/ssl.h>
#include <mariadb/conncpp.hpp>
#include "Random.h"

inline sql::bytes HashPassword(const std::string& password, const std::string& salt)
{
    const std::string content = password + salt;
    unsigned char tokenHash[SHA512_DIGEST_LENGTH]{};
    SHA512((const unsigned char*)content.c_str(), content.size(), tokenHash);

    sql::bytes bytes;
    bytes.assign((const char*)tokenHash, SHA512_DIGEST_LENGTH);

    return bytes;
}

inline sql::bytes HashToken(const std::string& token)
{
    unsigned char tokenHash[SHA512_DIGEST_LENGTH]{};
    SHA512((const unsigned char*)token.c_str(), token.size(), tokenHash);

    sql::bytes bytes;
    bytes.assign((const char*)tokenHash, SHA512_DIGEST_LENGTH);

    return bytes;
}

std::string GenerateToken()
{
    static std::string possibleLetters = {"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"};

    std::string token;

    for(int i = 0; i < 64; i++)
    {
        token.push_back(possibleLetters.at(Math::Random<size_t>(0, possibleLetters.length()-1)));
    }

    return token;
}