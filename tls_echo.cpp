#include <unistd.h>
#include <sys/wait.h>

#include <iostream>
#include <functional>
#include <thread>

#include <tls.h>

static int client(int fdr, int fdw);
static int server(int fdr, int fdw);

static pid_t spawn(std::function<int(int,int)> func, int &fdr, int &fdw);

int main()
{
    int fd[2][2];

    pid_t pid_client = spawn(&client, fd[0][0], fd[0][1]);
    pid_t pid_server = spawn(&server, fd[1][0], fd[1][1]);

    auto fwd = [](int fdr, int fdw)
    {
        char buf[1024] = {0};
        ssize_t nbytes = 0;
        do {
            nbytes = read(fdr, buf, 1024);
            write(fdw, buf, nbytes);
        } while (nbytes > 0);
        close(fdr);
        close(fdw);
    };

    std::thread fwd1(fwd, fd[0][0], fd[1][1]);
    std::thread fwd2(fwd, fd[1][0], fd[0][1]);

    fwd1.join();
    fwd2.join();

    waitpid(pid_client, nullptr, 0);
    waitpid(pid_server, nullptr, 0);

    std::cout << "bye!" << std::endl;

    return 0;
}


pid_t spawn(std::function<int(int,int)> func, int &fdr, int &fdw)
{
    int fd_w[2];
    int fd_r[2];

    if (pipe(fd_w) == -1) {
        std::cerr << "pipe() failed" << std::endl;
        return -1;
    }

    if (pipe(fd_r) == -1) {
        std::cerr << "pipe() failed" << std::endl;
        return -1;
    }

    const pid_t pid = fork();

    switch (pid) {
    case -1:
        return -1;
    case 0:
        // child process
        close(fd_w[0]);
        close(fd_r[1]);
        func(fd_r[0], fd_w[1]);
        close(fd_r[0]);
        close(fd_w[1]);
        exit(0);
    default:
        // parent process
        close(fd_w[1]);
        close(fd_r[0]);
        fdr = fd_w[0];
        fdw = fd_r[1];
        break;
    }

    return 0;
}

int client(int fd_read, int fd_write)
{
    static char buf[1024] = {0};
    struct tls *tls;
    struct tls_config *tls_config;
    const char *key_file = "client.key";
    const char *cert_file = "client.crt";
    const char *ca_file = "ca.crt";

    if (tls_init() != 0) {
        std::cerr << "tls_init() failed" << std::endl;
        return -1;
    }

    if ((tls = tls_client()) == NULL) {
        std::cerr << "tls_client() failed" << std::endl;
        return -1;
    }

    if ((tls_config = tls_config_new()) == NULL) {
        std::cerr << "tls_config_new() failed" << std::endl;
        return -1;
    }

    if (tls_config_set_key_file(tls_config, key_file) == -1) {
        std::cerr << "unable to set TLS key file " << key_file << std::endl;
        return -1;
    }
    if (tls_config_set_cert_file(tls_config, cert_file) == -1) {
        std::cerr << "unable to set TLS certificate file " << cert_file << std::endl;
        return -1;
    }
    if (tls_config_set_ca_file(tls_config, ca_file) == -1) {
        std::cerr << "unable to set root CA file " << ca_file << std::endl;
        return -1;
    }

    if (tls_configure(tls, tls_config) != 0) {
        std::cerr << "tls_configure() failed" << std::endl;
        return -1;
    }

    if (tls_connect_fds(tls, fd_read, fd_write, "echo server") != 0) {
        std::cerr << "error: " << tls_error(tls) << std::endl;
        return -1;
    }

    ssize_t nbytes = 0;
    do {
        nbytes = read(0, buf, 1024);
        if (nbytes > 0) {
            tls_write(tls, buf, nbytes);
            nbytes = tls_read(tls, buf, 1024);
            write(1, buf, nbytes);
        }
    } while (nbytes > 0);

    tls_close(tls);
    tls_free(tls);
    tls_config_free(tls_config);

    return 0;
}


int server(int fd_read, int fd_write)
{
    static char buf[1024] = {0};
    struct tls *tls;
    struct tls_config *tls_config;
    const char *key_file = "server.key";
    const char *cert_file = "server.crt";
    const char *ca_file = "ca.crt";

    if (tls_init() != 0) {
        std::cerr << "tls_init() failed" << std::endl;
        return -1;
    }

    if ((tls = tls_server()) == NULL) {
        std::cerr << "tls_server() failed" << std::endl;
        return -1;
    }

    if ((tls_config = tls_config_new()) == NULL) {
        std::cerr << "tls_config_new() failed" << std::endl;
        return -1;
    }

    // require certificate from client
    tls_config_verify_client(tls_config);

    if (tls_config_set_key_file(tls_config, key_file) == -1) {
        std::cerr << "unable to set TLS key file " << key_file << std::endl;
        return -1;
    }
    if (tls_config_set_cert_file(tls_config, cert_file) == -1) {
        std::cerr << "unable to set TLS certificate file " << cert_file << std::endl;
        return -1;
    }
    if (tls_config_set_ca_file(tls_config, ca_file) == -1) {
        std::cerr << "unable to set root CA file " << ca_file << std::endl;
        return -1;
    }

    tls_config_set_protocols(tls_config, TLS_PROTOCOLS_ALL);
    tls_config_set_ciphers(tls_config, "legacy");

    if (tls_configure(tls, tls_config) != 0) {
        std::cerr << "tls_configure() failed: " << tls_error(tls) << std::endl;
        return -1;
    }

    {
        struct tls *tls_cctx;
        ssize_t nbytes = 0;

        if (tls_accept_fds(tls, &tls_cctx, fd_read, fd_write) < 0) {
            std::cerr << "tls_accept_fds() failed: " << tls_error(tls) << std::endl;
            tls_cctx = NULL;
            return -1;
        }

        do {
            nbytes = tls_read(tls_cctx, buf, 1024);
            tls_write(tls_cctx, buf, nbytes);
        } while (nbytes > 0);

        if (read < 0) {
            std::cerr << "tls_read failed: " << tls_error(tls_cctx) << std::endl;
            return -1;
        }

        tls_close(tls_cctx);
        tls_free(tls_cctx);
    }

    tls_close(tls);
    tls_free(tls);
    tls_config_free(tls_config);

    return 0;
}
