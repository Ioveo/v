
#include "saia.h"
#include <poll.h>

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

int socket_create(int ipv6, int is_verify) {
    int domain = ipv6 ? AF_INET6 : AF_INET;
    int fd = socket(domain, SOCK_STREAM, 0);
    
    if (fd < 0) {
        return -1;
    }
    
    /* 仅扫端口阶段启用 RST 快速回收；验真阶段保留正常四次挥手 */
    if (!is_verify) {
        struct linger sl;
        sl.l_onoff = 1;
        sl.l_linger = 0;
        setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&sl, sizeof(sl));
    }

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
    
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT;
    result = poll(&pfd, 1, timeout_ms);
    if (result <= 0) return -1;
    
    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
    
    return error ? -1 : 0;
}

int socket_send_all(int fd, const char *data, size_t len, int timeout_ms) {
    if (fd < 0 || !data || len == 0) return -1;

    size_t sent_total = 0;
    while (sent_total < len) {
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLOUT;
        if (poll(&pfd, 1, timeout_ms) <= 0) {
            return -1;
        }

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

    size_t recv_cap = size;
    if (delimiter) {
        if (size <= 1) return -1;
        recv_cap = size - 1;
    }

    size_t delimiter_len = 0;
    if (delimiter && *delimiter) {
        delimiter_len = strlen(delimiter);
    } else {
        delimiter = NULL;
    }

    size_t total_received = 0;
    uint64_t start_ms = get_current_time_ms();

    while (total_received < recv_cap) {
        uint64_t now_ms = get_current_time_ms();
        int remain_ms = timeout_ms;
        if (timeout_ms > 0 && now_ms > start_ms) {
            uint64_t elapsed = now_ms - start_ms;
            if (elapsed >= (uint64_t)timeout_ms) break;
            remain_ms = timeout_ms - (int)elapsed;
        }

        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;

        int pr = poll(&pfd, 1, remain_ms);
        if (pr <= 0) break;

        size_t prev_total = total_received;
        int received = recv(fd, buf + total_received, recv_cap - total_received, 0);
        if (received <= 0) break;
        total_received += (size_t)received;

        if (delimiter && delimiter_len > 0 && total_received >= delimiter_len) {
            size_t scan_from = 0;
            if (prev_total >= (delimiter_len - 1)) {
                scan_from = prev_total - (delimiter_len - 1);
            }
            for (size_t i = scan_from; i + delimiter_len <= total_received; i++) {
                if (memcmp(buf + i, delimiter, delimiter_len) == 0) {
                    buf[total_received] = '\0';
                    return (int)total_received;
                }
            }
        }
    }

    if (delimiter && total_received > 0) {
        buf[total_received] = '\0';
    }
    return total_received > 0 ? (int)total_received : -1;
}
