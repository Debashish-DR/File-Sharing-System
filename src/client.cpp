#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <ctime>
#include <iomanip>
#include "tls_wrapper.h"

#define PORT 9090
#define DOWNLOADS_DIR "client_downloads"

void createDirectory(const std::string &path) { mkdir(path.c_str(), 0777); }

void initializeClient()
{
    createDirectory(DOWNLOADS_DIR);
    std::cout << "=== Secure File Sharing Client (TLS 1.3) ===\n";
}

void clearInputBuffer()
{
    std::cin.clear();
    std::cin.ignore(10000, '\n');
}

// Read a text frame ending in "END"
std::string receiveMessage(TLSWrapper &tls)
{
    std::string response;
    while (true)
    {
        std::string chunk = tls.secureRecv();
        if (chunk.empty())
            break;
        response += chunk;
        size_t endpos = response.find("END");
        if (endpos != std::string::npos)
            return response.substr(0, endpos);
    }
    return response;
}

bool authenticate(TLSWrapper &tls)
{
    std::cout << "\n🔐 Authentication Required\n";
    std::cout << "Default Accounts: admin/admin123, user1/password1, user2/password2\n";

    int attempts = 0;
    while (attempts < 3)
    {
        (void)receiveMessage(tls); // server prompt

        std::string username, password;
        std::cout << "Username: ";
        std::cin >> username;
        std::cout << "Password: ";
        std::cin >> password;

        tls.secureSend(username + ":" + password);

        std::string response = receiveMessage(tls);
        if (response == "AUTH_SUCCESS")
        {
            std::cout << "✅ Authentication successful!\n\n";
            return true;
        }
        else
        {
            std::cout << "❌ " << response << "\n";
            attempts++;
        }
    }
    std::cout << "🚫 Too many failed attempts\n";
    return false;
}

bool fileExists(const std::string &filename)
{
    std::ifstream file(filename);
    return file.good();
}

// Drain bytes until a marker appears; used when skipping a download
static void drainUntilMarker(TLSWrapper &tls, const std::string &marker)
{
    std::string acc;
    while (true)
    {
        std::string chunk = tls.secureRecv(); // blocking read is fine: server already sent file + FILE_END
        if (chunk.empty())
            break;
        acc += chunk;
        if (acc.find(marker) != std::string::npos)
            break;
        if (acc.size() > (1 << 22))
            acc.erase(0, acc.size() - 8192); // safety cap
    }
}

// Drain pending control frames so they don't show up late
static void drainPending(TLSWrapper &tls)
{
    while (tls.hasData(0))
    {
        std::string msg = receiveMessage(tls);
        if (msg.empty())
            break;
        if (msg.rfind("ERROR:", 0) == 0 || msg.rfind("AUTH_", 0) == 0 || msg == "GOODBYE")
            std::cout << msg << "\n";
        else
            break;
    }
}

void downloadFile(TLSWrapper &tls)
{
    // Expect: FILE_INFO:<name>:<size>END  or  ERROR:...END
    std::string header = receiveMessage(tls);

    if (header.rfind("FILE_INFO:", 0) == 0)
    {
        const size_t name_start = 10;
        const size_t size_sep = header.find(":", name_start);
        if (size_sep == std::string::npos)
        {
            std::cout << "❌ Bad header\n";
            return;
        }

        const std::string filename = header.substr(name_start, size_sep - name_start);
        const size_t file_size = std::stoul(header.substr(size_sep + 1));
        const std::string filepath = std::string(DOWNLOADS_DIR) + "/" + filename;

        if (fileExists(filepath))
        {
            std::cout << "⚠️ File already exists: " << filename << "\nOverwrite? (y/n): ";
            char choice;
            std::cin >> choice;
            clearInputBuffer();
            if (choice != 'y' && choice != 'Y')
            {
                // Server is already streaming the file; drain until FILE_END to keep protocol in sync.
                drainUntilMarker(tls, "FILE_END");
                std::cout << "📥 Download skipped\n";
                return;
            }
        }

        std::ofstream file(filepath, std::ios::binary);
        if (!file)
        {
            std::cout << "❌ Cannot open for write: " << filepath << "\n";
            return;
        }

        std::cout << "📥 Downloading (TLS): " << filename << " (" << file_size << " bytes)\n";

        size_t received = 0;
        std::string buffer;

        while (true)
        {
            std::string chunk = tls.secureRecv();
            if (chunk.empty())
                break;

            buffer += chunk;
            size_t pos = buffer.find("FILE_END");
            if (pos != std::string::npos)
            {
                if (pos > 0)
                {
                    file.write(buffer.data(), pos);
                    received += pos;
                }
                break;
            }
            else
            {
                file.write(buffer.data(), buffer.size());
                received += buffer.size();
                buffer.clear();
            }

            if (file_size > 0)
            {
                int progress = static_cast<int>((received * 100) / file_size);
                std::cout << "\r📊 Progress: " << std::setw(3) << progress << "% [";
                int bars = (progress * 20) / 100;
                for (int i = 0; i < 20; ++i)
                    std::cout << (i < bars ? "=" : " ");
                std::cout << "] " << received << "/" << file_size << " bytes";
                std::cout.flush();
            }
        }

        std::cout << "\r" << std::string(80, ' ') << "\r";
        std::cout << "✅ Download completed: " << filename << " (" << received << " bytes)\n";
        file.close();
    }
    else if (header.rfind("ERROR:", 0) == 0)
    {
        std::cout << "❌ " << header << "\n";
    }
    else
    {
        std::cout << "❌ Unexpected response from server\n";
    }
}

void uploadFile(TLSWrapper &tls, const std::string &filename)
{
    if (!fileExists(filename))
    {
        std::cout << "❌ File not found: " << filename << "\n";
        return;
    }

    tls.secureSend(filename);

    // If server replies immediately (e.g., already exists), show it and abort
    if (tls.hasData(300))
    {
        std::string early = receiveMessage(tls);
        if (!early.empty() && early.rfind("ERROR:", 0) == 0)
        {
            std::cout << "⚠️ " << early << "\n";
            return;
        }
    }

    std::ifstream file(filename, std::ios::binary);
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::cout << "📤 Uploading (TLS): " << filename << " (" << file_size << " bytes)\n";

    char buffer[1024];
    size_t sent = 0;

    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        std::string chunk(buffer, file.gcount());
        tls.secureSend(chunk);
        sent += chunk.size();

        if (file_size > 0)
        {
            int progress = static_cast<int>((sent * 100) / file_size);
            std::cout << "\r📊 Progress: " << std::setw(3) << progress << "% [";
            int bars = (progress * 20) / 100;
            for (int i = 0; i < 20; ++i)
                std::cout << (i < bars ? "=" : " ");
            std::cout << "] " << sent << "/" << file_size << " bytes";
            std::cout.flush();
        }
    }

    tls.secureSend("UPLOAD_END");

    std::string response = receiveMessage(tls);

    std::cout << "\r" << std::string(80, ' ') << "\r";
    if (response == "UPLOAD_SUCCESS")
    {
        std::cout << "✅ Upload completed: " << filename << " (" << sent << " bytes)\n";
    }
    else if (response.find("File already exists") != std::string::npos)
    {
        std::cout << "⚠️ " << response << "\n";
    }
    else if (response.rfind("ERROR:", 0) == 0)
    {
        std::cout << "❌ " << response << "\n";
    }
    else
    {
        std::cout << "❌ Upload failed\n";
    }

    file.close();
}

int main()
{
    initializeClient();

    TLSWrapper tls;
    if (!tls.initializeClient())
    {
        std::cerr << "❌ TLS initialization failed\n";
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cout << "❌ Connection failed\n";
        return -1;
    }

    std::cout << "✅ Connected to server\n";

    if (!tls.connectToServer(sock))
    {
        std::cout << "❌ TLS handshake failed\n";
        close(sock);
        return -1;
    }

    if (!authenticate(tls))
    {
        close(sock);
        return -1;
    }

    bool session_active = true;
    while (session_active)
    {
        std::string menu = receiveMessage(tls);
        std::cout << menu << std::endl;

        int choice;
        std::cout << "---> ";
        std::cin >> choice;
        clearInputBuffer();

        tls.secureSend(std::to_string(choice));

        switch (choice)
        {
        case 0:
            session_active = false;
            std::cout << receiveMessage(tls) << std::endl;
            break;

        case 1:
        {
            int file_num;
            std::cout << "Enter file number to download: ";
            std::cin >> file_num;
            clearInputBuffer();

            if (file_num < 0)
            {
                std::cout << "❌ Invalid file number\n";
                break;
            }

            tls.secureSend(std::to_string(file_num));
            downloadFile(tls);
            break;
        }

        case 2:
        {
            std::string filename;
            std::cout << "Enter filename to upload: ";
            std::cin >> filename;
            clearInputBuffer();
            uploadFile(tls, filename);
            break;
        }

        case 3:
            break;

        default:
            std::cout << "Invalid choice\n";
            break;
        }

        if (session_active && choice != 3)
        {
            drainPending(tls);
            std::cout << "Press Enter to continue...";
            std::cin.get();
        }
    }

    close(sock);
    std::cout << "🔒 Secure session ended\n";
    return 0;
}