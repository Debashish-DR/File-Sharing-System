#ifndef TLS_WRAPPER_H
#define TLS_WRAPPER_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>

class TLSWrapper
{
private:
    SSL_CTX *ctx;
    SSL *ssl;
    int sock_fd;

public:
    TLSWrapper() : ctx(nullptr), ssl(nullptr), sock_fd(-1) {}
    ~TLSWrapper() { cleanup(); }

    bool initializeServer()
    {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx)
            return false;

        if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
            return false;
        if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
            return false;
        if (!SSL_CTX_check_private_key(ctx))
            return false;

        return true;
    }

    bool initializeClient()
    {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx)
            return false;

        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        return true;
    }

    // Defensive: free any previous SSL before starting a new handshake
    bool acceptConnection(int client_socket)
    {
        sock_fd = client_socket;

        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock_fd);

        int result = SSL_accept(ssl);
        if (result <= 0)
        {
            int err = SSL_get_error(ssl, result);
            std::cerr << "❌ TLS accept failed: " << err << std::endl;
            SSL_free(ssl);
            ssl = nullptr;
            return false;
        }
        std::cout << "🔐 TLS connection established" << std::endl;
        return true;
    }

    bool connectToServer(int sock)
    {
        sock_fd = sock;

        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock_fd);

        int result = SSL_connect(ssl);
        if (result <= 0)
        {
            int err = SSL_get_error(ssl, result);
            std::cerr << "❌ TLS connect failed: " << err << std::endl;
            SSL_free(ssl);
            ssl = nullptr;
            return false;
        }
        std::cout << "🔐 TLS connection established" << std::endl;
        return true;
    }

    // Non-blocking probe for data
    bool hasData(int timeout_ms)
    {
        if (ssl && SSL_pending(ssl) > 0)
            return true;
        if (sock_fd < 0)
            return false;
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock_fd, &rfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int ret = select(sock_fd + 1, &rfds, NULL, NULL, &tv);
        return (ret > 0 && FD_ISSET(sock_fd, &rfds));
    }

    int pending() { return ssl ? SSL_pending(ssl) : 0; }

    int secureSend(const std::string &data)
    {
        if (!ssl)
            return -1;
        return SSL_write(ssl, data.c_str(), (int)data.length());
    }

    std::string secureRecv()
    {
        if (!ssl)
            return "";
        char buffer[4096];
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0)
        {
            buffer[bytes] = '\0';
            return std::string(buffer, bytes);
        }
        return "";
    }

    void cleanup()
    {
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (sock_fd != -1)
        {
            close(sock_fd);
            sock_fd = -1;
        }
        if (ctx)
        {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
    }
};

#endif
