#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <map>
#include <ctime>
#include <arpa/inet.h>
#include "tls_wrapper.h"

#define PORT 9090
#define SERVER_FILES_DIR "server_files"
#define UPLOADS_DIR "server_uploads"
#define LOGS_DIR "logs"

std::map<std::string, std::string> users = {
    {"admin", "admin123"},
    {"user1", "password1"},
    {"user2", "password2"}};

static void createDirectory(const std::string &path) { mkdir(path.c_str(), 0777); }

static std::string nowStr()
{
    std::time_t t = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%a %b %e %H:%M:%S %Y", std::localtime(&t));
    return std::string(buf);
}

static void logAppend(const std::string &file, const std::string &line)
{
    std::ofstream f(file, std::ios::app);
    if (!f)
        return;
    f << nowStr() << "\n - " << line << "\n";
}

static void initializeDirectories()
{
    createDirectory(SERVER_FILES_DIR);
    createDirectory(UPLOADS_DIR);
    createDirectory(LOGS_DIR);
}

static bool authenticateUser(const std::string &username, const std::string &password)
{
    auto it = users.find(username);
    return (it != users.end() && it->second == password);
}

static std::vector<std::string> listFiles()
{
    std::vector<std::string> files;
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir(SERVER_FILES_DIR)) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..") && ent->d_name[0] != '.')
                files.push_back(ent->d_name);
        }
        closedir(dir);
    }
    return files;
}

static void sendMenu(TLSWrapper &tls)
{
    auto files = listFiles();
    std::stringstream menu;

    menu << "\n=== Secure File Sharing Server (TLS 1.3) ===\n";
    menu << "Available Files (" << files.size() << "):\n";
    menu << "---------------------------\n";

    if (files.empty())
    {
        menu << "No files available\n";
    }
    else
    {
        for (size_t i = 0; i < files.size(); ++i)
        {
            std::string filepath = std::string(SERVER_FILES_DIR) + "/" + files[i];
            std::ifstream f(filepath, std::ios::binary | std::ios::ate);
            size_t size = f ? static_cast<size_t>(f.tellg()) : 0;
            menu << i + 1 << ". " << files[i] << " (" << size << " bytes)\n";
        }
    }

    menu << "---------------------------\n";
    menu << "0. Exit\n";
    menu << "1. Download file\n";
    menu << "2. Upload file\n";
    menu << "3. Refresh\n";
    menu << "Enter choice: END";

    tls.secureSend(menu.str());
}

static void sendFile(TLSWrapper &tls, const std::string &filename)
{
    std::string filepath = std::string(SERVER_FILES_DIR) + "/" + filename;
    std::ifstream file(filepath, std::ios::binary);
    if (!file)
    {
        tls.secureSend("ERROR:File not foundEND");
        logAppend(std::string(LOGS_DIR) + "/server.log", "DOWNLOAD failed (not found): " + filename);
        return;
    }

    file.seekg(0, std::ios::end);
    size_t file_size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    tls.secureSend("FILE_INFO:" + filename + ":" + std::to_string(file_size) + "END");

    char buffer[1024];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        tls.secureSend(std::string(buffer, file.gcount()));
    }

    tls.secureSend("FILE_END");
    std::cout << "📤 File sent (TLS): " << filename << " (" << file_size << " bytes)\n";
    logAppend(std::string(LOGS_DIR) + "/server.log",
              "DOWNLOAD: " + filename + " (" + std::to_string(file_size) + " bytes)");
}

static bool fileExists(const std::string &filename)
{
    std::ifstream file(filename);
    return file.good();
}

static void receiveFile(TLSWrapper &tls, const std::string &filename)
{
    std::string filepath = std::string(UPLOADS_DIR) + "/" + filename;

    if (fileExists(filepath))
    {
        tls.secureSend("ERROR:File already exists on serverEND");
        std::cout << "⚠️ Upload skipped: " << filename << " already exists\n";
        logAppend(std::string(LOGS_DIR) + "/server.log", "UPLOAD skipped (exists): " + filename);
        return;
    }

    std::ofstream file(filepath, std::ios::binary);
    size_t total_bytes = 0;

    while (true)
    {
        std::string data = tls.secureRecv();
        if (data.empty())
            break;

        size_t pos = data.find("UPLOAD_END");
        if (pos != std::string::npos)
        {
            if (pos > 0)
            {
                file.write(data.c_str(), pos);
                total_bytes += pos;
            }
            break;
        }
        file.write(data.c_str(), data.length());
        total_bytes += data.length();
    }

    file.close();

    if (total_bytes > 0)
    {
        tls.secureSend("UPLOAD_SUCCESSEND");
        std::cout << "📥 File received (TLS): " << filename << " (" << total_bytes << " bytes)\n";
        logAppend(std::string(LOGS_DIR) + "/server.log",
                  "UPLOAD: " + filename + " (" + std::to_string(total_bytes) + " bytes)");
    }
    else
    {
        tls.secureSend("UPLOAD_FAILEDEND");
        logAppend(std::string(LOGS_DIR) + "/server.log", "UPLOAD failed: " + filename);
    }
}

static bool authenticateClient(TLSWrapper &tls, std::string &outUser)
{
    int attempts = 0;
    while (attempts < 3)
    {
        tls.secureSend("Enter username:passwordEND");

        std::string credentials = tls.secureRecv();
        size_t separator = credentials.find(':');
        if (separator != std::string::npos)
        {
            std::string username = credentials.substr(0, separator);
            std::string password = credentials.substr(separator + 1);
            if (authenticateUser(username, password))
            {
                tls.secureSend("AUTH_SUCCESSEND");
                std::cout << "🔓 Authenticated: " << username << "\n";
                outUser = username;
                logAppend(std::string(LOGS_DIR) + "/security.log", "User authenticated: " + username);
                return true;
            }
        }

        attempts++;
        tls.secureSend("AUTH_FAILED:Attempt " + std::to_string(attempts) + "/3END");
        logAppend(std::string(LOGS_DIR) + "/security.log", "Auth failed (attempt " + std::to_string(attempts) + ")");
    }
    tls.secureSend("AUTH_BLOCKEDEND");
    logAppend(std::string(LOGS_DIR) + "/security.log", "Auth blocked");
    return false;
}

int main()
{
    initializeDirectories();

    TLSWrapper tlsGlobal;
    if (!tlsGlobal.initializeServer())
    {
        std::cerr << "❌ TLS initialization failed\n";
        return 1;
    }

    std::cout << "=== Secure File Sharing Server (TLS 1.3) ===\n";

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return 1;
    }

    int one = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind");
        std::cerr << "⚠️ Port " << PORT << " is likely in use. Stop the other service or change PORT.\n";
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 16) < 0)
    {
        perror("listen");
        close(server_fd);
        return 1;
    }

    std::cout << "🚀 Server started on port " << PORT << "\n";
    logAppend(std::string(LOGS_DIR) + "/server.log", "Server started on port " + std::to_string(PORT));

    while (true)
    {
        int client_socket = accept(server_fd, NULL, NULL);
        if (client_socket < 0)
        {
            perror("accept");
            continue;
        }

        std::cout << "\n📞 New client connected\n";
        logAppend(std::string(LOGS_DIR) + "/server.log", "Client connected");

        if (!tlsGlobal.acceptConnection(client_socket))
        {
            std::cout << "❌ TLS handshake failed\n";
            logAppend(std::string(LOGS_DIR) + "/server.log", "TLS handshake failed");
            close(client_socket);
            continue;
        }

        std::string user;
        if (!authenticateClient(tlsGlobal, user))
        {
            logAppend(std::string(LOGS_DIR) + "/security.log", "Client disconnected (auth failure)");
            close(client_socket);
            continue;
        }

        bool session_active = true;
        while (session_active)
        {
            sendMenu(tlsGlobal);

            std::string choice_str = tlsGlobal.secureRecv();
            int choice = atoi(choice_str.c_str());

            switch (choice)
            {
            case 0:
                session_active = false;
                tlsGlobal.secureSend("GOODBYEEND");
                if (!user.empty())
                    logAppend(std::string(LOGS_DIR) + "/server.log", "User logged out: " + user);
                break;

            case 1:
            {
                std::string file_num_str = tlsGlobal.secureRecv();
                int selection = atoi(file_num_str.c_str());
                auto files = listFiles();
                if (selection > 0 && selection <= (int)files.size())
                {
                    sendFile(tlsGlobal, files[selection - 1]);
                    if (!user.empty())
                        logAppend(std::string(LOGS_DIR) + "/server.log", user + " downloaded " + files[selection - 1]);
                }
                else
                {
                    tlsGlobal.secureSend("ERROR:Invalid selectionEND");
                }
                break;
            }

            case 2:
            {
                std::string filename = tlsGlobal.secureRecv();
                if (!filename.empty())
                {
                    receiveFile(tlsGlobal, filename);
                    if (!user.empty())
                        logAppend(std::string(LOGS_DIR) + "/server.log", user + " attempted upload: " + filename);
                }
                break;
            }

            case 3:
                break;

            default:
                tlsGlobal.secureSend("ERROR:Invalid choiceEND");
                break;
            }
        }

        close(client_socket);
        std::cout << "🔌 Client disconnected\n";
        logAppend(std::string(LOGS_DIR) + "/server.log", "Client disconnected");
    }

    close(server_fd);
    return 0;
}
