#ifndef COMMON_H
#define COMMON_H

#include <string>

#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_USERS 10
#define SESSION_TIMEOUT 300 // 5 minutes

struct User
{
    std::string username;
    std::string password;
    bool isActive;
};

#endif
