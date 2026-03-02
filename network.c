
#include "saia.h"

#ifndef _WIN32
#include <poll.h>
#endif

static int network_initialized = 0;

int network_init(void) {
    if (network_initialized) return 0;
    
    #ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }
    #endif
    
    network_initialized = 1;
    return 0;
}

void network_cleanup(void) {
    if (!network_initialized) return;
    
    #ifdef _WIN32
    WSACleanup();
    #endif
    
    network_initialized = 0;
}

int socket_create(int ipv6) {
    int domain = ipv6 ? AF_INET6 : AF_INET;
    int fd = socket(domain, SOCK_STREAM, 0);
    
    if (fd < 0) {
        return -1;
    }
    
    /* 立即释放连接，减少 TIME_WAIT/CLOSE_WAIT 累积 */
    struct linger sl;
    sl.l_onoff = 1;
    sl.l_linger = 0;
    setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&sl, sizeof(sl));

    /* 允许地址复用 */
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse));
#endif

    return fd;
}

int socket_close(int fd) {
    if (fd < 0) return -1;
    
    #ifdef _WIN32
    closesocket(fd);
    #else
    close(fd);
    #endif
    
    return 0;
}

int socket_set_nonblocking(int fd) {
    if (fd < 0) return -1;
    
    #ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode);
    #else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    #endif
}

int socket_set_timeout(int fd, int sec) {
    if (fd < 0) return -1;
    
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
    
    return 0;
}

int ip_parse(const char *str, ip_addr_t *addr) {
    if (!str || !addr) return -1;
    
    memset(addr, 0, sizeof(ip_addr_t));
    
    if (strstr(str, ":")) {
        addr->is_ipv6 = 1;
        strncpy(addr->ip, str, sizeof(addr->ip) - 1);
        return 0;
    }
    
    /* Validate it's a real IPv4 address using inet_pton into a temp buffer */
    struct in_addr tmp;
    if (inet_pton(AF_INET, str, &tmp) <= 0) {
        return -1;
    }
    
    strncpy(addr->ip, str, sizeof(addr->ip) - 1);
    return 0;
}

int ip_to_string(const ip_addr_t *addr, char *buf, size_t size) {
    if (!addr || !buf || size == 0) return -1;
    
    strncpy(buf, addr->ip, size - 1);
    buf[size - 1] = '\0';
    return 0;
}

int ip_is_valid(const char *str) {
    if (!str) return 0;
    
    ip_addr_t addr;
    return ip_parse(str, &addr) == 0;
}

int socket_connect_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
    socket_set_nonblocking(fd);
    
    int result = connect(fd, addr, addrlen);
    
    if (result == 0) {
        return 0;
    }
    
    #ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        return -1;
    }
    #else
    if (errno != EINPROGRESS) {
        return -1;
    }
    #endif
    
#ifdef _WIN32
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(fd, &write_fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    result = select(fd + 1, NULL, &write_fds, NULL, &tv);
    if (result <= 0) return -1;
#else
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT;
    result = poll(&pfd, 1, timeout_ms);
    if (result <= 0) return -1;
#endif
    
    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
    
    return error ? -1 : 0;
}

int socket_send_all(int fd, const char *data, size_t len, int timeout_ms) {
    if (fd < 0 || !data || len == 0) return -1;

    size_t sent_total = 0;
    while (sent_total < len) {
#ifdef _WIN32
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(fd, &write_fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        if (select(fd + 1, NULL, &write_fds, NULL, &tv) <= 0) {
            return -1;
        }
#else
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLOUT;
        if (poll(&pfd, 1, timeout_ms) <= 0) {
            return -1;
        }
#endif

        int n = send(fd, data + sent_total, len - sent_total, 0);
        if (n <= 0) {
            return -1;
        }
        sent_total += (size_t)n;
    }

    return 0;
}

int socket_recv_until(int fd, char *buf, size_t size, const char *delimiter, int timeout_ms) {
    if (fd < 0 || !buf || size == 0) return -1;

#ifdef _WIN32
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (select(fd + 1, &read_fds, NULL, NULL, &tv) <= 0) {
        return -1;
    }
#else
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0) {
        return -1;
    }
#endif
    
    size_t recv_cap = size;
    if (delimiter) {
        if (size <= 1) return -1;
        recv_cap = size - 1;
    }

    int received = recv(fd, buf, recv_cap, 0);
    if (received <= 0) return -1;

    if (delimiter) {
        buf[received] = '\0';
    }
    return received;
}
