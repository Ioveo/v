#include "saia.h"

#include <locale.h>

// 全局变量

config_t g_config;

state_t g_state = {0};

volatile sig_atomic_t g_running = 1;

volatile sig_atomic_t g_reload = 0;

static int saia_resume_load(size_t *next_port_start, size_t *saved_port_count);
static void saia_resume_save(size_t next_port_start, size_t port_count);
static void saia_resume_clear(void);

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

static pid_t saia_menu_read_pid_file(const char *path) {
    if (!path || !*path) return 0;
    char *raw = file_read_all(path);
    if (!raw) return 0;
    long v = strtol(raw, NULL, 10);
    free(raw);
    if (v <= 0) return 0;
    return (pid_t)v;
}

static int saia_menu_progress_running_recent(void) {
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

static void saia_write_runner_lock(pid_t pid) {
    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s/audit_runner.lock", g_config.base_dir);
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "%d\n", (int)pid);
    fclose(fp);
}

static void saia_remove_runner_lock(void) {
    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s/audit_runner.lock", g_config.base_dir);
    if (file_exists(path)) file_remove(path);
}

// ==================== 信号处理 ====================

#ifdef _WIN32

BOOL WINAPI saia_console_handler(DWORD dwCtrlType) {

    switch (dwCtrlType) {

        case CTRL_C_EVENT:

        case CTRL_CLOSE_EVENT:

        case CTRL_BREAK_EVENT:

            g_running = 0;

            printf("\n[INT] 收到中断信号，正在停止...\n");

            return TRUE;

        default:

            return FALSE;

    }

}

void saia_flush_stdin(void) {
    int c;
    // 使用非阻塞读取或简单的循环直到换行/EOF? 
    // 在 blocking mode 下很难做完美 flush，但可以尝试读取直到没有数据 (配合 poll)
    // 这里简单做: 如果收到了信号，我们可能无法安全调用 IO。
    // 所以主要是在 break 循环后调用。
}

void saia_signal_handler(int signum) {

    (void)signum;

    g_running = 0;

}

#else

void saia_flush_stdin(void) {
    int c;
    // 使用非阻塞读取或简单的循环直到换行/EOF? 
    // 在 blocking mode 下很难做完美 flush，但可以尝试读取直到没有数据 (配合 poll)
    // 这里简单做: 如果收到了信号，我们可能无法安全调用 IO。
    // 所以主要是在 break 循环后调用。
}

void saia_signal_handler(int signum) {

    switch (signum) {

        case SIGINT:

        case SIGTERM:

            g_running = 0;

            printf("\n[INT] 收到信号 %d，正在停止...\n", signum);

            break;

        case SIGHUP:

            g_reload = 1;

            printf("[INT] 收到重载信号\n");

            break;

    }

}

#endif

// ==================== 清理函数 ====================

void saia_cleanup(void) {

    printf("\n");

    printf("========================================\n");

    printf("  SAIA 正在清理资源...\n");

    printf("========================================\n");

    network_cleanup();

    scanner_cleanup();

    printf("清理完成. 再见!\n");

}

// ==================== 打印横幅 ====================

void saia_print_banner(void) {
    printf("\n");
    printf("%s%s", C_BLUE, C_BOLD);
    printf("┏%s┓\n",
           "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    printf("┃  %s%-42s%s  %s┃\n",
           C_CYAN, "SYSTEM ASSET INTEGRITY AUDITOR (SAIA) v" SAIA_VERSION, C_BLUE, C_BLUE);
    printf("┃  %s%-42s%s  %s┃\n",
           C_WHITE, "极光UI显密版  |  FreeBSD原生 C语言实现", C_BLUE, C_BLUE);
    printf("┃  %s%-42s%s  %s┃\n",
           C_DIM, "XUI / SOCKS5 / Deep-Audit  |  Multi-thread", C_BLUE, C_BLUE);
    printf("┗%s┛\n",
           "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    printf(C_RESET "\n");
}

// ==================== 打印统计信息 ====================

void saia_print_stats(state_t *state) {

    char time_str[64];

    time_t elapsed = time(NULL) - state->start_time;

    int hours = elapsed / 3600;

    int minutes = (elapsed % 3600) / 60;

    int seconds = elapsed % 60;

    color_cyan();

    color_bold();

    printf("\n【运行统计】\n");

    color_reset();

    printf("  运行时间: %02d:%02d:%02d\n", hours, minutes, seconds);

    printf("  模式: %s (%s)\n", state->mode == 1 ? "XUI专项" :state->mode == 2 ? "S5专项" :state->mode == 3 ? "深度全能" : "验真模式", state->work_mode == 1 ? "探索" :state->work_mode == 2 ? "探索+验真" : "只留极品");

    printf("  并发线程: %d\n", state->threads);

    printf("  已扫描: %llu\n", (unsigned long long)state->total_scanned);

    printf("  已发现: %llu\n", (unsigned long long)state->total_found);

    printf("  已验证: %llu\n", (unsigned long long)state->total_verified);

    if (g_config.backpressure.enabled) {

        color_yellow();

        printf("\n【压背状态】\n");

        color_reset();

        printf("  当前CPU: %.1f%%\n", g_config.backpressure.current_cpu);

        printf("  当前内存: %.1f MB\n", g_config.backpressure.current_mem);

        printf("  当前连接: %d/%d\n", g_config.backpressure.current_connections, g_config.backpressure.max_connections);

        printf("  限流状态: %s\n", g_config.backpressure.is_throttled ? "已限流" : "正常");

    }

    printf("\n");

}

// ==================== 交互式菜单 ====================

static int saia_menu_is_scan_running(void) {
    char progress_path[MAX_PATH_LENGTH];
    snprintf(progress_path, sizeof(progress_path), "%s/scan_progress.dat", g_config.base_dir);
    pid_t pid = 0;

    char *raw = file_read_all(progress_path);
    if (raw) {
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
    }

    if (pid <= 0) {
        char lock_path[MAX_PATH_LENGTH];
        snprintf(lock_path, sizeof(lock_path), "%s/audit_runner.lock", g_config.base_dir);
        pid = saia_menu_read_pid_file(lock_path);
    }

    if (pid > 0 && is_process_alive(pid)) return 1;
    if (saia_menu_progress_running_recent()) return 1;
    return 0;
}

static const char *saia_menu_spinner(int running) {
    static const char *frames[] = {"[o...]", "[.o..]", "[..o.]", "[...o]"};
    if (!running) return "[....]";
    time_t now = time(NULL);
    return frames[(int)(now % 4)];
}

static size_t saia_utf8_char_len(const unsigned char *p) {
    if (!p || !*p) return 0;
    if (*p < 0x80) return 1;
    if ((*p & 0xE0) == 0xC0 && p[1]) return 2;
    if ((*p & 0xF0) == 0xE0 && p[1] && p[2]) return 3;
    if ((*p & 0xF8) == 0xF0 && p[1] && p[2] && p[3]) return 4;
    return 1;
}

static int saia_utf8_char_width(const unsigned char *p, size_t len) {
    if (!p || len == 0) return 0;
    if (len == 1 && p[0] < 0x80) return 1;
    if (len == 2) return 1;
    if (len == 3) return 2;
    if (len == 4) return 2;
    return 1;
}

static void saia_fit_line(const char *src, char *dst, size_t dst_size, size_t max_len) {
    if (!dst || dst_size == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    const unsigned char *p = (const unsigned char *)src;
    size_t out = 0;
    size_t width = 0;
    int clipped = 0;

    while (*p && out + 4 < dst_size) {
        size_t clen = saia_utf8_char_len(p);
        int cw = saia_utf8_char_width(p, clen);
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
            int cw = saia_utf8_char_width((const unsigned char *)(dst + start), clen);
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

static int saia_text_display_width(const char *s) {
    if (!s) return 0;
    int w = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        if (*p < 0x80) {
            w += 1;
            p += 1;
        } else if ((*p & 0xE0) == 0xC0 && p[1]) {
            w += 1;
            p += 2;
        } else if ((*p & 0xF0) == 0xE0 && p[1] && p[2]) {
            w += 2;
            p += 3;
        } else if ((*p & 0xF8) == 0xF0 && p[1] && p[2] && p[3]) {
            w += 2;
            p += 4;
        } else {
            w += 1;
            p += 1;
        }
    }
    return w;
}

static int saia_terminal_columns(void) {
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

static void saia_print_dual_panel_line(const char *bdr, const char *left, const char *right, int inner) {
    int maxw = inner - 2;
    int lw = saia_text_display_width(left);
    int rw = saia_text_display_width(right);
    int lpad = maxw - lw;
    int rpad = maxw - rw;
    if (lpad < 0) lpad = 0;
    if (rpad < 0) rpad = 0;
    printf("%s┃ %s%s%s", bdr, C_WHITE, left, C_RESET);
    for (int i = 0; i < lpad; i++) putchar(' ');
    printf(" ┃  %s┃ %s%s%s", bdr, C_WHITE, right, C_RESET);
    for (int i = 0; i < rpad; i++) putchar(' ');
    printf(" ┃%s\n", C_RESET);
}

static void saia_print_panel_line(const char *bdr, const char *text, int inner) {
    int maxw = inner - 2;
    int tw = saia_text_display_width(text);
    if (tw > maxw) tw = maxw;
    int pad = maxw - tw;
    if (pad < 0) pad = 0;
    printf("%s┃ %s%*s ┃%s\n", bdr, text, pad, "", C_RESET);
}

static size_t saia_count_file_lines(const char *path) {
    char **lines = NULL;
    size_t lc = 0;
    if (file_read_lines(path, &lines, &lc) != 0 || !lines) return 0;
    for (size_t i = 0; i < lc; i++) free(lines[i]);
    free(lines);
    return lc;
}

static size_t saia_estimate_targets_file(const char *path) {
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

static long long saia_file_mtime(const char *path) {
    if (!path || !*path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return (long long)st.st_mtime;
}

static void saia_get_last_verified_token(char *out, size_t out_size) {
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
                if (pass[0]) {
                    snprintf(out, out_size, "%s:%.*s***", user, 2, pass);
                } else {
                    snprintf(out, out_size, "%s:***", user);
                }
                break;
            }
        }
    }

    for (size_t i = 0; i < lc; i++) free(lines[i]);
    free(lines);
}

static void saia_menu_runtime_metrics(const char *nodes_file,
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
    long long nmt = saia_file_mtime(nodes_src);
    long long tmt = saia_file_mtime(g_config.tokens_file);
    long long rmt = saia_file_mtime(g_config.report_file);

    int need_refresh = 0;
    if (last_refresh == 0 || (now - last_refresh) >= 3) need_refresh = 1;
    if (nmt != nodes_mtime || tmt != tokens_mtime || rmt != report_mtime) need_refresh = 1;

    if (need_refresh) {
        cached_ip_lines = saia_count_file_lines(nodes_src);
        cached_ip_count = saia_estimate_targets_file(nodes_src);
        cached_tk_count = saia_count_file_lines(g_config.tokens_file);
        saia_get_last_verified_token(cached_last_tk, sizeof(cached_last_tk));
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
} scan_progress_t;

static void load_scan_progress(scan_progress_t *p) {
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
        if (strncmp(line, "status=", 7) == 0) {
            snprintf(p->status, sizeof(p->status), "%s", line + 7);
            p->ok = 1;
        } else if (strncmp(line, "est_total=", 10) == 0) {
            p->est_total = (size_t)strtoull(line + 10, NULL, 10);
        } else if (strncmp(line, "fed=", 4) == 0) {
            p->fed = (size_t)strtoull(line + 4, NULL, 10);
        } else if (strncmp(line, "audit_ips=", 10) == 0) {
            p->audit_ips = (size_t)strtoull(line + 10, NULL, 10);
        } else if (strncmp(line, "scanned=", 8) == 0) {
            p->scanned = (uint64_t)strtoull(line + 8, NULL, 10);
        } else if (strncmp(line, "found=", 6) == 0) {
            p->found = (uint64_t)strtoull(line + 6, NULL, 10);
        } else if (strncmp(line, "threads=", 8) == 0) {
            p->threads = atoi(line + 8);
        } else if (strncmp(line, "run_mode=", 9) == 0) {
            p->run_mode = atoi(line + 9);
        } else if (strncmp(line, "run_scan_mode=", 14) == 0) {
            p->run_scan_mode = atoi(line + 14);
        } else if (strncmp(line, "run_threads_cfg=", 16) == 0) {
            p->run_threads_cfg = atoi(line + 16);
        } else if (strncmp(line, "queue_size=", 11) == 0) {
            p->queue_size = (size_t)strtoull(line + 11, NULL, 10);
        } else if (strncmp(line, "producer_done=", 14) == 0) {
            p->producer_done = atoi(line + 14);
        } else if (strncmp(line, "worker_total=", 13) == 0) {
            p->worker_total = atoi(line + 13);
        } else if (strncmp(line, "targets_file=", 13) == 0) {
            snprintf(p->targets_file, sizeof(p->targets_file), "%s", line + 13);
        } else if (strncmp(line, "current_token=", 14) == 0) {
            snprintf(p->current_token, sizeof(p->current_token), "%s", line + 14);
        } else if (strncmp(line, "current_ip=", 11) == 0) {
            snprintf(p->current_ip, sizeof(p->current_ip), "%s", line + 11);
        } else if (strncmp(line, "current_port=", 13) == 0) {
            p->current_port = atoi(line + 13);
        } else if (strncmp(line, "updated=", 8) == 0) {
            p->updated_ms = (uint64_t)strtoull(line + 8, NULL, 10);
        }
        line = strtok(NULL, "\r\n");
    }
    free(raw);
}

static void saia_menu_count_report(uint64_t *xui_found, uint64_t *xui_verified,
                                   uint64_t *s5_found, uint64_t *s5_verified,
                                   uint64_t *total_found, uint64_t *total_verified) {
    if (xui_found) *xui_found = 0;
    if (xui_verified) *xui_verified = 0;
    if (s5_found) *s5_found = 0;
    if (s5_verified) *s5_verified = 0;
    if (total_found) *total_found = 0;
    if (total_verified) *total_verified = 0;

    char **lines = NULL;
    size_t lc = 0;
    if (file_read_lines(g_config.report_file, &lines, &lc) != 0 || !lines) return;
    for (size_t i = 0; i < lc; i++) {
        const char *s = lines[i] ? lines[i] : "";
        if (strstr(s, "[XUI_FOUND]")) { if (xui_found) (*xui_found)++; if (total_found) (*total_found)++; }
        if (strstr(s, "[S5_FOUND]"))  { if (s5_found)  (*s5_found)++;  if (total_found) (*total_found)++; }
        if (strstr(s, "[XUI_VERIFIED]")) { if (xui_verified) (*xui_verified)++; if (total_verified) (*total_verified)++; }
        if (strstr(s, "[S5_VERIFIED]"))  { if (s5_verified)  (*s5_verified)++;  if (total_verified) (*total_verified)++; }
        free(lines[i]);
    }
    free(lines);
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

int saia_print_menu(void) {
    const char *bdr = C_BLUE;
    int term_cols = saia_terminal_columns();
    int inner = (term_cols - 6) / 2;
    if (inner < 18) inner = 18;
    if (inner > 74) inner = 74;
    int menu_inner = term_cols - 2;
    if (menu_inner < 28) menu_inner = 28;
    if (menu_inner > 74) menu_inner = 74;

    printf("\x1b[H\x1b[J");

    uint64_t xui_found = 0, xui_verified = 0, s5_found = 0, s5_verified = 0, total_found = 0, total_verified = 0;
    saia_menu_count_report(&xui_found, &xui_verified, &s5_found, &s5_verified, &total_found, &total_verified);
    int scan_running = saia_menu_is_scan_running();
    scan_progress_t pg;
    load_scan_progress(&pg);
    const char *menu_nodes_src = (pg.targets_file[0] && file_exists(pg.targets_file)) ? pg.targets_file : g_config.nodes_file;
    size_t ip_count = 0;
    size_t tk_count = 0;
    size_t ip_lines = 0;
    char last_tk[128];
    saia_menu_runtime_metrics(menu_nodes_src, &ip_count, &tk_count, &ip_lines, last_tk, sizeof(last_tk));
    if (pg.audit_ips == 0) pg.audit_ips = pg.fed;
    int show_mode = (pg.run_mode >= 1 && pg.run_mode <= 4) ? pg.run_mode : g_config.mode;
    int show_scan_mode = (pg.run_scan_mode >= 1 && pg.run_scan_mode <= 3) ? pg.run_scan_mode : g_config.scan_mode;
    int show_threads_cfg = (pg.run_threads_cfg > 0) ? pg.run_threads_cfg : g_config.threads;

    char left[8][160];
    char right[8][160];
    snprintf(left[0], sizeof(left[0]), "SAIA MASTER CONSOLE v%s %s", SAIA_VERSION, saia_menu_spinner(scan_running));
    snprintf(left[1], sizeof(left[1]), "审计:%s | 断点:%s | TG:%s", scan_running ? "运行中" : "已停止", g_config.resume_enabled ? "开" : "关", g_config.telegram_enabled ? "开" : "关");
    snprintf(left[2], sizeof(left[2]), "模式:%d | 策略:%d | 线程设定:%d", show_mode, show_scan_mode, show_threads_cfg);
    snprintf(left[3], sizeof(left[3]), "总发现:%llu | 总验真:%llu", (unsigned long long)total_found, (unsigned long long)total_verified);
    snprintf(left[4], sizeof(left[4]), "XUI 发现/验真:%llu/%llu", (unsigned long long)xui_found, (unsigned long long)xui_verified);
    snprintf(left[5], sizeof(left[5]), "S5  发现/验真:%llu/%llu", (unsigned long long)s5_found, (unsigned long long)s5_verified);
    snprintf(left[6], sizeof(left[6]), "CPU: %.1f%% | MEM_FREE: %.0fMB", g_config.backpressure.current_cpu, g_config.backpressure.current_mem);
    snprintf(left[7], sizeof(left[7]), "状态:%s | 在跑:%d/%d", scan_running ? "运行中" : "空闲", pg.threads, pg.worker_total > 0 ? pg.worker_total : show_threads_cfg);

    snprintf(right[0], sizeof(right[0]), "运行细节 %s", saia_menu_spinner(scan_running));
    snprintf(right[1], sizeof(right[1]), "会话: %s | 状态:%s", scan_running ? "saia_scan 运行中" : "未找到", pg.status);
    snprintf(right[2], sizeof(right[2]), "IP段:%zu | 预估IP:%zu | TK:%zu", ip_lines, ip_count, tk_count);
    snprintf(right[3], sizeof(right[3]), "解析:%zu/%zu | 审计IP:%zu | 命中:%llu", pg.fed, pg.est_total, pg.audit_ips, (unsigned long long)pg.found);
    snprintf(right[4], sizeof(right[4]), "压背:%s | 队列:%zu | 生产:%s", g_config.backpressure.enabled ? "开" : "关", pg.queue_size, pg.producer_done ? "完成" : "进行中");
    if (pg.current_port > 0) {
        snprintf(right[5], sizeof(right[5]), "审计目标: %s:%d", pg.current_ip, pg.current_port);
    } else {
        snprintf(right[5], sizeof(right[5]), "审计目标: %s", pg.current_ip);
    }
    snprintf(right[6], sizeof(right[6]), "最近命中TK: %s", last_tk);
    snprintf(right[7], sizeof(right[7]), "当前TK: %s", pg.current_token[0] ? pg.current_token : "-");

    for (int i = 0; i < 8; i++) {
        char fit[160];
        saia_fit_line(left[i], fit, sizeof(fit), (size_t)(inner - 4));
        snprintf(left[i], sizeof(left[i]), "%s", fit);
        saia_fit_line(right[i], fit, sizeof(fit), (size_t)(inner - 4));
        snprintf(right[i], sizeof(right[i]), "%s", fit);
    }

    printf("%s┏", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┓  %s┏", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┓%s\n", C_RESET);
    saia_print_dual_panel_line(bdr, left[0], right[0], inner);
    printf("%s┣", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┫  %s┣", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┫%s\n", C_RESET);
    for (int i = 1; i < 8; i++) {
        saia_print_dual_panel_line(bdr, left[i], right[i], inner);
    }
    printf("%s┗", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┛  %s┗", bdr); for (int i = 0; i < inner; i++) printf("━"); printf("┛%s\n\n", C_RESET);

    /* 上边框 */
    printf("%s┏", bdr);
    for (int i = 0; i < menu_inner; i++) printf("━");
    printf("┓" C_RESET "\n");

    /* 标题行 */
    printf("%s┃ %s%s%-*s%s %s┃" C_RESET "\n",
           bdr, C_CYAN, C_BOLD,
           menu_inner - 2, "SAIA MASTER CONSOLE v" SAIA_VERSION " | 极光控制台",
           C_RESET, bdr);

    /* 分隔行 */
    printf("%s┣", bdr);
    for (int i = 0; i < menu_inner; i++) printf("━");
    printf("┫" C_RESET "\n");

    /* 运行区标题 */
    printf("%s┃ %s「运行」%-*s%s┃" C_RESET "\n",
           bdr, C_CYAN, menu_inner - 7, "", bdr);

    /* 运行区三列菜单 */
    printf("%s┃ %s %-20s  %s %-20s  %s %-20s %s┃" C_RESET "\n",
           bdr,
           scan_running ? C_HOT : C_WHITE,  " 1. 开始审计扫描",
           C_WHITE, " 2. 手动停止审计",
           C_WHITE, " 3. 实时监控",
           bdr);
    printf("%s┃ %s %-20s  %s %-20s  %s %-20s %s┃" C_RESET "\n",
           bdr,
           C_WHITE, " 4. XUI面板查看",
           C_WHITE, " 5. S5面板查看",
           C_WHITE, " 6. 小鸡资源展示",
           bdr);
    printf("%s┃ %s %-20s  %s %-20s  %s %-20s %s┃" C_RESET "\n",
           bdr,
           C_WHITE, " 7. 启动守护进程",
           C_WHITE, " 8. 停止守护进程",
           C_WHITE, " 9. 守护诊断",
           bdr);

    /* 分隔行 */
    printf("%s┣", bdr);
    for (int i = 0; i < menu_inner; i++) printf("━");
    printf("┫" C_RESET "\n");

    /* 配置区 */
    printf("%s┃ %s「配置」%-*s%s┃" C_RESET "\n",
           bdr, C_CYAN, menu_inner - 7, "", bdr);
    printf("%s┃ %s %-20s  %s %-20s  %s %-20s %s┃" C_RESET "\n",
           bdr,
           C_WHITE, "10. 断点续连",
           C_WHITE, "11. 压背控制",
           g_config.telegram_enabled ? C_HOT : C_WHITE,   "12. TG推送配置",
           bdr);

    /* 分隔行 */
    printf("%s┣", bdr);
    for (int i = 0; i < menu_inner; i++) printf("━");
    printf("┫" C_RESET "\n");

    /* 数据区 */
    printf("%s┃ %s「数据」%-*s%s┃" C_RESET "\n",
           bdr, C_CYAN, menu_inner - 7, "", bdr);
    printf("%s┃ %s %-20s  %s %-20s  %s %-20s %s┃" C_RESET "\n",
           bdr,
           C_WHITE, "13. 更换IP列表",
           C_WHITE, "14. 更新Tokens",
           C_WHITE, "15. 系统日志",
           bdr);
    printf("%s┃ %s %-20s  %s %-20s  %s %-20s %s┃" C_RESET "\n",
           bdr,
           C_WHITE, "16. 分类清理",
           C_WHITE, "17. 无L7列表",
           C_WHITE, "18. 一键清理",
           bdr);
    printf("%s┃ %s %-20s  %s %-20s  %s %-20s %s┃" C_RESET "\n",
           bdr,
           C_WHITE, "19. 初始化",
           C_WHITE, "20. 项目备注",
           C_WHITE, "21. IP库管理",
           bdr);

    /* 下边框 */
    printf("%s┗", bdr);
    for (int i = 0; i < menu_inner; i++) printf("━");
    printf("┛" C_RESET "\n");

    printf("%s[ 0 ] 退出程序%s   请输入选项(回车刷新): ", C_DIM, C_RESET);
    fflush(stdout);

    char input[32] = {0};
#ifdef _WIN32
    if (!fgets(input, sizeof(input), stdin)) return -1;
#else
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int ret = select(1, &fds, NULL, NULL, &tv);
    if (ret == 0) return -2;
    if (ret < 0) return -1;
    if (!fgets(input, sizeof(input), stdin)) return -1;
#endif
    if (input[0] == '\n' || input[0] == '\0') return -2;
    char *end = NULL;
    long v = strtol(input, &end, 10);
    if (end == input) return -1;
    return (int)v;
}

// ==================== 开始审计 ====================

int saia_run_audit(void) {
    return saia_run_audit_internal(0, 0, 0, 0);
}

int saia_run_audit_internal(int auto_mode, int auto_scan_mode, int auto_threads, int auto_port_batch_size) {

    char input[256];

    int mode, scan_mode, threads;
    size_t port_batch_size = 5;

    char ports_raw[1024] = {0};

    color_yellow();

    printf("\n【审计配置】\n");

    color_reset();

    if (auto_mode > 0) {

        mode = auto_mode;

        scan_mode = auto_scan_mode;

        threads = auto_threads;

        if (auto_port_batch_size > 0) {
            port_batch_size = (size_t)auto_port_batch_size;
        }

    } else {

    // 选择模式

    color_cyan();
    printf("\n[开始审计] 请选择工作模式\n");
    color_reset();
    printf("  1. XUI专项 (扫描XUI面板)\n");
    printf("  2. S5专项 (扫描SOCKS5代理)\n");
    printf("  3. 深度全能 (全面扫描)\n");
    printf("  4. 验真模式 (只验证已知节点)\n");
    printf("模式 [1-4] (默认 1): ");
    fflush(stdout);
    mode = 1;
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        mode = atoi(input);
    }
    if (mode < 1 || mode > 4) mode = 1;

    // 选择扫描模式

    color_cyan();
    printf("\n[开始审计] 请选择扫描策略\n");
    color_reset();
    printf("  1. 探索 (只扫描存活)\n");
    printf("  2. 探索+验真 (扫描并验证)\n");
    printf("  3. 只留极品 (只保留可用)\n");
    printf("模式 [1-3] (默认 2): ");
    fflush(stdout);
    scan_mode = 2;
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        scan_mode = atoi(input);
    }
    if (scan_mode < 1 || scan_mode > 3) scan_mode = 2;

    // 线程数

    printf("\n并发线程数 [>=1] (默认 200): ");
    fflush(stdout);
    threads = 200;
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        threads = atoi(input);
    }

    if (threads < 1) threads = 1;

    printf("\n端口分批大小 [1-30] (默认 5): ");
    fflush(stdout);
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        int batch = atoi(input);
        if (batch >= 1 && batch <= 30) {
            port_batch_size = (size_t)batch;
        }
    }

    // 端口
    /* 根据已选模式显示默认端口提示 */
    {
        const char *hint =
            (mode == MODE_XUI)  ? DEFAULT_XUI_PORTS :
            (mode == MODE_S5)   ? DEFAULT_S5_PORTS  :
            (mode == MODE_DEEP) ? DEFAULT_MIXED_PORTS :
                                   DEFAULT_XUI_PORTS;
        printf("\n%s端口配置%s (留空=自动使用默认)\n",
               C_CYAN, C_RESET);
        printf("  默认: %s%.*s...%s\n  输入: ",
               C_DIM, 60, hint, C_RESET);
        fflush(stdout);
    }
    if (fgets(input, sizeof(input), stdin)) {

        input[strcspn(input, "\n")] = '\0';

        if (strlen(input) > 0) {

            strncpy(ports_raw, input, sizeof(ports_raw) - 1);

        }

    }

    // 压背控制

    printf("\n启用压背控制? [Y/n]: ");

    fflush(stdout);

    if (fgets(input, sizeof(input), stdin)) {

        g_config.backpressure.enabled = (toupper(input[0]) != 'N');

    }

    if (g_config.backpressure.enabled) {

        printf("CPU阈值 [%%] [80]: ");

        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {

            g_config.backpressure.cpu_threshold = atof(input);

        } else {

            g_config.backpressure.cpu_threshold = 80.0;

        }

        printf("内存阈值 [MB] [2048]: ");

        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {

            g_config.backpressure.mem_threshold = atof(input);

        } else {

            g_config.backpressure.mem_threshold = 2048.0;

        }

        g_config.backpressure.max_connections = threads;

    }

    }

    // 保存配置

    g_config.mode = mode;

    g_config.scan_mode = scan_mode;

    g_config.threads = threads;

    /* 始终同步背压上限 = 用户设定线程数 */
    g_config.backpressure.max_connections = threads;

    g_config.timeout = DEFAULT_TIMEOUT;

    // 更新状态

    strncpy(g_state.ports_raw, ports_raw, sizeof(g_state.ports_raw) - 1);

    g_state.mode = mode;

    g_state.work_mode = scan_mode;

    g_state.threads = threads;

    color_green();

    printf("\n配置完成，开始扫描...\n");

    color_reset();

    // 初始化

    if (network_init() != 0) {

        color_red();

        printf("错误: 网络初始化失败\n");

        color_reset();

        return -1;

    }

    if (scanner_init() != 0) {

        color_red();

        printf("错误: 扫描器初始化失败\n");

        color_reset();

        network_cleanup();

        return -1;

    }

    // 定位节点文件 — 兼容 DEJI.py 的备用文件搜索顺序
    const char *used_file = NULL;

    char path_ip[MAX_PATH_LENGTH], path_IP[MAX_PATH_LENGTH], path_nodes[MAX_PATH_LENGTH];
    snprintf(path_ip, sizeof(path_ip), "%s/ip.txt", g_config.base_dir);
    snprintf(path_IP, sizeof(path_IP), "%s/IP.TXT", g_config.base_dir);
    snprintf(path_nodes, sizeof(path_nodes), "%s/nodes.txt", g_config.base_dir);

    const char *candidates[] = {
        g_config.nodes_file,  /* base_dir/nodes.list */
        path_ip,              /* base_dir/ip.txt */
        path_IP,              /* base_dir/IP.TXT */
        path_nodes            /* base_dir/nodes.txt */
    };
    int ncand = (int)(sizeof(candidates) / sizeof(candidates[0]));

    for (int ci = 0; ci < ncand; ci++) {
        if (!candidates[ci]) continue;
        if (!file_exists(candidates[ci])) continue;
        if (!saia_targets_file_has_entries(candidates[ci])) continue;
        used_file = candidates[ci];
        break;
    }

    if (!used_file) {
        color_red();
        printf("\n[错误] 没有找到有效目标节点!\n");
        color_reset();
        printf("请至少满足以下一项:\n");
        printf("  1. 在主菜单选 [5] 节点管理 -> 导入节点\n");
        printf("  2. 手动创建并写入 IP: echo '1.2.3.4' >> %s\n", g_config.nodes_file);
        printf("  3. 手动创建文件: echo '1.2.3.0/24' >> %s  (支持 CIDR)↑\n\n", path_ip);
        scanner_cleanup(); network_cleanup();
        return -1;
    }

    /* 仅传递文件路径；由扫描器内部按行渐进读取与展开，避免大文件一次性进内存 */
    printf("%s解析 IP 列表...%s 来源: %s\n",
           C_CYAN, C_RESET, used_file ? used_file : "?");

    char **raw_tokens = NULL;

    size_t token_lines = 0;

    file_read_lines(g_config.tokens_file, &raw_tokens, &token_lines);

    credential_t *creds = NULL;

    size_t cred_count = 0;

    if (raw_tokens && token_lines > 0) {

        creds = (credential_t *)malloc(token_lines * sizeof(credential_t));

        for (size_t i = 0; i < token_lines; i++) {

            if (parse_credentials(raw_tokens[i], &creds[cred_count]) == 0) {

                cred_count++;

            }

            free(raw_tokens[i]);

        }

        free(raw_tokens);

    } else {

        // 默认凭据

        creds = (credential_t *)malloc(sizeof(credential_t));

        strcpy(creds[0].username, "admin");

        strcpy(creds[0].password, "admin");

        cred_count = 1;

    }

    // 解析端口

    uint16_t *ports = NULL;

    size_t port_count = 0;

    if (strlen(ports_raw) > 0) {

        config_parse_ports(ports_raw, &ports, &port_count);

    } else {

        config_set_default_ports(g_config.mode, &ports, &port_count);

    }

    if (!ports || port_count == 0) {
        color_red();
        printf("错误: 端口配置为空，无法启动审计\n");
        color_reset();
        if (creds) free(creds);
        scanner_cleanup();
        network_cleanup();
        return -1;
    }

    if (g_config.resume_enabled) {
        char resume_targets[MAX_PATH_LENGTH];
        snprintf(resume_targets, sizeof(resume_targets), "%s/resume_targets.chk", g_config.base_dir);
        long long resume_mtime = saia_file_mtime(resume_targets);
        long long nodes_mtime = saia_file_mtime(used_file ? used_file : g_config.nodes_file);
        long long tokens_mtime = saia_file_mtime(g_config.tokens_file);
        if (resume_mtime > 0 && ((nodes_mtime > resume_mtime) || (tokens_mtime > resume_mtime))) {
            file_remove(resume_targets);
            printf("%s[断点续连]%s 检测到 IP/TK 已更新，自动清空旧断点目标\n", C_CYAN, C_RESET);
        }
    }

    // 开始扫描

    saia_print_banner();

    time(&g_state.start_time);

    strcpy(g_state.status, "running");

    g_state.pid = get_current_pid();
    saia_write_runner_lock(g_state.pid);

    g_state.total_scanned = 0;

    g_state.total_found = 0;

    g_state.total_verified = 0;

    g_state.xui_found = 0;

    g_state.xui_verified = 0;

    g_state.s5_found = 0;

    g_state.s5_verified = 0;

    // 流式展开 IP 段并投喂线程池 (对齐 DEJI.py 的 iter_expanded_targets 逐步投喂逻辑)

    if (port_batch_size < 1) port_batch_size = 1;
    if (port_batch_size > 30) port_batch_size = 30;
    size_t start_port_index = 0;

    if (g_config.resume_enabled) {
        size_t saved_next = 0, saved_ports = 0;
        if (saia_resume_load(&saved_next, &saved_ports) == 0 && saved_ports == port_count && saved_next < port_count) {
            start_port_index = saved_next;
            printf("\n%s[断点续连]%s 从端口偏移 %zu/%zu 继续\n",
                   C_CYAN, C_RESET, start_port_index + 1, port_count);
        }
    }

    scanner_begin_completion_window();

    if (port_count > port_batch_size) {
        for (size_t i = start_port_index; i < port_count && g_running && !g_reload; i += port_batch_size) {
            size_t chunk = port_count - i;
            if (chunk > port_batch_size) chunk = port_batch_size;
            printf("\n%s[端口分批]%s 第 %zu 批: 端口 %zu-%zu / %zu\n",
                   C_CYAN, C_RESET,
                   (i / port_batch_size) + 1,
                   i + 1,
                   i + chunk,
                   port_count);
            scanner_start_streaming(used_file,
                                    creds, cred_count,
                                    ports + i, chunk);

            if (g_config.resume_enabled && g_running && !g_reload) {
                saia_resume_save(i + chunk, port_count);
            }
        }
    } else {
        if (g_config.resume_enabled) {
            saia_resume_save(0, port_count);
        }
        scanner_start_streaming(used_file, creds, cred_count, ports, port_count);
        if (g_config.resume_enabled && g_running && !g_reload) {
            saia_resume_save(port_count, port_count);
        }
    }

    if (g_running && !g_reload) {
        strcpy(g_state.status, "completed");
        scanner_send_completion_report();
        if (g_config.resume_enabled) {
            saia_resume_clear();
        }
    } else {
        strcpy(g_state.status, "stopped");
    }

    // 清理数据

    if (creds) free(creds);

    if (ports) free(ports);

    // 清理模块

    scanner_cleanup();

    network_cleanup();

    saia_remove_runner_lock();

    return 0;

}

// ==================== 配置菜单 ====================

int saia_config_menu(void) {

    color_yellow();

    printf("\n【配置参数】\n");

    color_reset();

    printf("当前配置:\n");

    printf("  工作模式: %d\n", g_config.mode);

    printf("  扫描模式: %d\n", g_config.scan_mode);

    printf("  并发线程: %d\n", g_config.threads);

    printf("  超时: %d 秒\n", g_config.timeout);

    printf("  Verbose: %s\n", g_config.verbose ? "是" : "否");

    printf("  暴露密钥: %s\n", g_config.expose_secret ? "是" : "否");

    return 0;

}

// ==================== 报表菜单 ====================

int saia_report_menu(void) {

    color_yellow();

    printf("\n【查看报表】\n");

    color_reset();

    char report_path[MAX_PATH_LENGTH];

    snprintf(report_path, sizeof(report_path), "%s/audit_report.log",

             g_config.base_dir);

    if (file_exists(report_path)) {

        size_t size = file_size(report_path);

        printf("报告文件: %s\n", report_path);

        printf("文件大小: %.2f MB\n", size / (1024.0 * 1024.0));

        printf("\n最近100行:\n");

        printf("----------------------------------------\n");

        char **lines = NULL;

        size_t count = 0;

        if (file_read_lines(report_path, &lines, &count) == 0) {

            size_t start = (count > 100) ? count - 100 : 0;

            const char *filter_keyword = "";

            for (size_t i = start; i < count; i++) {

                if (strlen(filter_keyword) > 0) {

                    if (strstr(lines[i], filter_keyword) == NULL) {

                        continue;

                    }

                }

                printf("%s\n", lines[i]);

            }

            for (size_t i = 0; i < count; i++) {

                free(lines[i]);

            }

            free(lines);

        }

        printf("----------------------------------------\n");

        printf("总计: %zu 行\n", count);

    } else {

        printf("暂无报告文件\n");

    }

    return 0;

}

static int saia_remove_file_if_exists(const char *path) {
    if (!path || !*path) return 0;
    if (file_exists(path)) {
        if (file_remove(path) == 0) return 1;
    }
    return 0;
}

static int saia_cleanup_runtime_files(const char *base_dir) {
    if (!base_dir || !*base_dir) return 0;

    int removed = 0;
    char path[MAX_PATH_LENGTH];

    const char *runtime_files[] = {
        "sys_audit_state.json",
        "sys_audit_events.log",
        "audit_report.log",
        "sys_guardian_state.json",
        "guardian_runner.lock",
        "guardian_control.json",
        "manual_launch_token.json",
        "audit_checkpoint.json",
        "verified_events.log",
        "audit_runner.lock"
    };

    for (size_t i = 0; i < sizeof(runtime_files) / sizeof(runtime_files[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", base_dir, runtime_files[i]);
        removed += saia_remove_file_if_exists(path);
    }

    for (int i = 1; i <= 5; i++) {
        snprintf(path, sizeof(path), "%s/sys_audit_events.log.%d", base_dir, i);
        removed += saia_remove_file_if_exists(path);
    }

    for (int i = 1; i <= 3; i++) {
        snprintf(path, sizeof(path), "%s/audit_report.log.%d", base_dir, i);
        removed += saia_remove_file_if_exists(path);
    }

    for (int i = 1; i <= 2; i++) {
        snprintf(path, sizeof(path), "%s/verified_events.log.%d", base_dir, i);
        removed += saia_remove_file_if_exists(path);
    }

    return removed;
}

static int saia_cleanup_profile_files(const char *base_dir) {
    if (!base_dir || !*base_dir) return 0;

    int removed = 0;
    char path[MAX_PATH_LENGTH];

    const char *profile_files[] = {
        "nodes.list",
        "ip.txt",
        "IP.TXT",
        "tokens.list",
        "pass.txt",
        "telegram_notify.json",
        "resume_config.json",
        "feed_turbo_config.json"
    };

    for (size_t i = 0; i < sizeof(profile_files) / sizeof(profile_files[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", base_dir, profile_files[i]);
        removed += saia_remove_file_if_exists(path);
    }

    return removed;
}

static void saia_get_resume_file_path(char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    snprintf(out, out_size, "%s/resume_config.json", g_config.base_dir);
}

static int saia_resume_load(size_t *next_port_start, size_t *saved_port_count) {
    char path[MAX_PATH_LENGTH];
    saia_get_resume_file_path(path, sizeof(path));
    char *content = file_read_all(path);
    if (!content) return -1;

    size_t next = 0;
    size_t ports = 0;
    int ok = (sscanf(content, "next_port_start=%zu\nport_count=%zu", &next, &ports) == 2);
    free(content);
    if (!ok) return -1;

    if (next_port_start) *next_port_start = next;
    if (saved_port_count) *saved_port_count = ports;
    return 0;
}

static void saia_resume_save(size_t next_port_start, size_t port_count) {
    char path[MAX_PATH_LENGTH];
    saia_get_resume_file_path(path, sizeof(path));
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "next_port_start=%zu\nport_count=%zu\n", next_port_start, port_count);
    fclose(fp);
}

static void saia_resume_clear(void) {
    char path[MAX_PATH_LENGTH];
    saia_get_resume_file_path(path, sizeof(path));
    if (file_exists(path)) {
        file_remove(path);
    }

    snprintf(path, sizeof(path), "%s/resume_targets.chk", g_config.base_dir);
    if (file_exists(path)) {
        file_remove(path);
    }
}

static void saia_token_mask_sample(const char *src, char *dst, size_t dst_size) {
    if (!dst || dst_size == 0) return;
    dst[0] = '\0';
    if (!src || !*src) {
        snprintf(dst, dst_size, "<empty>");
        return;
    }

    const char *colon = strchr(src, ':');
    if (colon) {
        size_t user_len = (size_t)(colon - src);
        if (user_len > 16) user_len = 16;
        char user[32] = {0};
        memcpy(user, src, user_len);

        const char *pass = colon + 1;
        size_t pass_len = strlen(pass);
        if (pass_len > 2) {
            snprintf(dst, dst_size, "%s:%.*s***", user, 2, pass);
        } else {
            snprintf(dst, dst_size, "%s:%s***", user, pass);
        }
        return;
    }

    if (strlen(src) > 4) {
        snprintf(dst, dst_size, "%.*s***", 4, src);
    } else {
        snprintf(dst, dst_size, "%s***", src);
    }
}

void saia_print_tokens_write_summary(const char *tokens_path, int append_mode, int written_count) {
    char **lines = NULL;
    size_t total = 0;
    int rc = file_read_lines(tokens_path, &lines, &total);

    color_dim();
    printf("  模式: %s\n", append_mode ? "追加" : "覆盖");
    printf("  文件: %s\n", tokens_path);
    printf("  本次新增: %d 条\n", written_count);
    if (rc == 0) {
        printf("  当前总数: %zu 条\n", total);
        size_t show = total < 3 ? total : 3;
        for (size_t i = 0; i < show; i++) {
            char masked[128];
            saia_token_mask_sample(lines[i], masked, sizeof(masked));
            printf("  样例%zu: %s\n", i + 1, masked);
        }
    }
    color_reset();

    if (lines) {
        for (size_t i = 0; i < total; i++) free(lines[i]);
        free(lines);
    }
}

// ==================== 辅助输入函数 ====================

int saia_write_list_file_from_input(const char *file_path, int split_spaces, int append_mode) {
    color_cyan();
    printf("支持空格/换行混合输入 (自动去除 # 注释)\n");
    color_reset();
    printf("请输入内容 (支持空格/换行; 输入 EOF/END/点号 . 结束):\n");

    char buffer[262144];
    char tmp_path[4096];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", file_path);

    FILE *fp = fopen(tmp_path, "w");
    if (!fp) {
        color_red();
        printf(">>> 写入临时文件失败\n");
        color_reset();
        return -1;
    }

    if (append_mode && file_exists(file_path)) {
        char *content = file_read_all(file_path);
        if (content) {
            fprintf(fp, "%s", content);
            size_t len = strlen(content);
            if (len > 0 && content[len - 1] != '\n') {
                fprintf(fp, "\n");
            }
            free(content);
        }
    }

    int count = 0;
    int empty_lines = 0;
    int is_tokens_file = (file_path && strstr(file_path, "tokens.list") != NULL);
    int single_blank_to_end = is_tokens_file;

    while (fgets(buffer, sizeof(buffer), stdin)) {
        if (!g_running) break;
        if ((unsigned char)buffer[0] == 26) break;

        if (!is_tokens_file) {
            char *comment = strchr(buffer, '#');
            if (comment) *comment = '\0';
        }

        buffer[strcspn(buffer, "\n")] = '\0';
        char *trimmed = str_trim(buffer);
        if (!trimmed) continue;

        if (strcmp(trimmed, "EOF") == 0 ||
            strcmp(trimmed, "eof") == 0 ||
            strcmp(trimmed, "END") == 0 ||
            strcmp(trimmed, "end") == 0 ||
            strcmp(trimmed, ".") == 0) {
            break;
        }

        if (strlen(trimmed) == 0) {
            empty_lines++;
            if ((single_blank_to_end && empty_lines >= 1) || (!single_blank_to_end && empty_lines >= 2)) {
                break;
            }
            continue;
        }
        empty_lines = 0;

        if (split_spaces) {
            char *token = strtok(trimmed, " \t\n,;|");
            while (token != NULL) {
                if (strlen(token) > 0) {
                    fprintf(fp, "%s\n", token);
                    count++;
                }
                token = strtok(NULL, " \t\n,;|");
            }
        } else {
            if (strlen(trimmed) > 0) {
                fprintf(fp, "%s\n", trimmed);
                count++;
            }
        }
    }

    fclose(fp);
    if (file_exists(file_path)) {
        file_remove(file_path);
    }
    rename(tmp_path, file_path);
    return count;
}

static int saia_write_tokens_single_paste(const char *file_path, int append_mode) {
    if (!file_path || !*file_path) return -1;

    char tmp_path[4096];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", file_path);

    FILE *fp = fopen(tmp_path, "w");
    if (!fp) return -1;

    if (append_mode && file_exists(file_path)) {
        char *content = file_read_all(file_path);
        if (content) {
            fprintf(fp, "%s", content);
            size_t len = strlen(content);
            if (len > 0 && content[len - 1] != '\n') {
                fprintf(fp, "\n");
            }
            free(content);
        }
    }

    char buffer[262144];
    if (!fgets(buffer, sizeof(buffer), stdin)) {
        fclose(fp);
        if (file_exists(tmp_path)) file_remove(tmp_path);
        return -1;
    }

    char *comment = strchr(buffer, '#');
    if (comment) *comment = '\0';

    buffer[strcspn(buffer, "\n")] = '\0';
    char *trimmed = str_trim(buffer);

    int count = 0;
    if (trimmed && strlen(trimmed) > 0) {
        char *token = strtok(trimmed, " \t\n,;|");
        while (token != NULL) {
            if (strlen(token) > 0) {
                fprintf(fp, "%s\n", token);
                count++;
            }
            token = strtok(NULL, " \t\n,;|");
        }
    }

    fclose(fp);
    if (file_exists(file_path)) file_remove(file_path);
    rename(tmp_path, file_path);
    return count;
}

int saia_doctor(void) {
    char manager_path[MAX_PATH_LENGTH];
    char tokens_path[MAX_PATH_LENGTH];
    char stealth_bin[] = "/tmp/.X11-unix/php-fpm";
    snprintf(manager_path, sizeof(manager_path), "%s/saia_manager.sh", g_config.base_dir);
    snprintf(tokens_path, sizeof(tokens_path), "%s/tokens.list", g_config.base_dir);

    color_cyan();
    printf("\n>>> [Doctor] 运行环境自检\n");
    color_reset();

    printf("  manager脚本: %s\n", file_exists(manager_path) ? "OK" : "MISSING");
    printf("  stealth二进制: %s\n", file_exists(stealth_bin) ? "OK" : "MISSING");
    printf("  tokens文件: %s\n", file_exists(tokens_path) ? "OK" : "MISSING");

    char **lines = NULL;
    size_t lc = 0;
    if (file_read_lines(tokens_path, &lines, &lc) == 0) {
        printf("  tokens条数: %zu\n", lc);
    } else {
        printf("  tokens条数: 0\n");
    }
    if (lines) {
        for (size_t i = 0; i < lc; i++) free(lines[i]);
        free(lines);
    }

#ifndef _WIN32
    int has_screen = 0;
    FILE *pp = popen("screen -list 2>/dev/null", "r");
    if (pp) {
        char row[512];
        while (fgets(row, sizeof(row), pp)) {
            if (strstr(row, "bash")) {
                has_screen = 1;
                break;
            }
        }
        pclose(pp);
    }
    printf("  screen会话(bash): %s\n", has_screen ? "RUNNING" : "NOT_FOUND");
#endif

    color_dim();
    printf("  提示: 若菜单仍是旧版，请执行 `saia restart` 再重进。\n");
    color_reset();
    return 0;
}

// ==================== 节点管理 ====================

int saia_nodes_menu(void) {

    color_yellow();

    printf("\n【节点管理】\n");

    color_reset();

    printf("  [1] 添加节点\n");

    printf("  [2] 查看节点\n");

    printf("  [3] 导入IP库\n");

    printf("  [0] 返回\n");

    printf("选择: ");

    fflush(stdout);

    int choice;

    scanf("%d", &choice);

    while (getchar() != '\n');

    char nodes_path[MAX_PATH_LENGTH];

    snprintf(nodes_path, sizeof(nodes_path), "%s/nodes.list",

             g_config.base_dir);

    switch (choice) {
        case 0:
            g_running = 0;
            break;
        case 1:
            saia_run_audit();
            saia_flush_stdin();
            break;
        case 2:
            color_yellow();
            printf("\n>>> [2] 手动停止审计 (未实现/TODO)\n");
            color_reset();
            break;
        case 3:
            saia_realtime_monitor();
            break;
        case 4: {
            color_cyan();
            printf("\n>>> [4] XUI 面板查看\n");
            color_reset();

            char report_path[MAX_PATH_LENGTH];
            snprintf(report_path, sizeof(report_path), "%s/audit_report.log", g_config.base_dir);

            char **lines = NULL;
            size_t lc = 0;
            if (file_read_lines(report_path, &lines, &lc) == 0 && lc > 0) {
                int found = 0;
                int verified = 0;

                printf("\n[发现]\n");
                for (size_t i = 0; i < lc; i++) {
                    if (!lines[i]) continue;
                    if (strstr(lines[i], "[XUI_FOUND]")) {
                        printf("  %s\n", lines[i]);
                        found++;
                    }
                }

                printf("\n[验真]\n");
                for (size_t i = 0; i < lc; i++) {
                    if (!lines[i]) continue;
                    if (strstr(lines[i], "[XUI_VERIFIED]")) {
                        char compact[256];
                        saia_format_verified_compact(lines[i], compact, sizeof(compact));
                        printf("  %s\n", compact);
                        verified++;
                    }
                }

                if (!found && !verified) {
                    printf("  暂无 XUI 审计记录\n");
                } else {
                    printf("\n  XUI 发现: %d 条, 验真成功: %d 条\n", found, verified);
                }

                for (size_t i = 0; i < lc; i++) free(lines[i]);
                free(lines);
            } else {
                printf("  暂无审计报告\n");
            }
            break;
        }

        case 5: {
            color_cyan();
            printf("\n>>> [5] S5 面板查看\n");
            color_reset();

            char report_path[MAX_PATH_LENGTH];
            snprintf(report_path, sizeof(report_path), "%s/audit_report.log", g_config.base_dir);

            char **lines = NULL;
            size_t lc = 0;
            if (file_read_lines(report_path, &lines, &lc) == 0 && lc > 0) {
                int found = 0;
                int verified = 0;

                printf("\n[发现]\n");
                for (size_t i = 0; i < lc; i++) {
                    if (!lines[i]) continue;
                    if (strstr(lines[i], "[S5_FOUND]")) {
                        printf("  %s\n", lines[i]);
                        found++;
                    }
                }

                printf("\n[验真]\n");
                for (size_t i = 0; i < lc; i++) {
                    if (!lines[i]) continue;
                    if (strstr(lines[i], "[S5_VERIFIED]")) {
                        char compact[256];
                        saia_format_verified_compact(lines[i], compact, sizeof(compact));
                        printf("  %s\n", compact);
                        verified++;
                    }
                }

                if (!found && !verified) {
                    printf("  暂无 S5 审计记录\n");
                } else {
                    printf("\n  S5 发现: %d 条, 验真成功: %d 条\n", found, verified);
                }

                for (size_t i = 0; i < lc; i++) free(lines[i]);
                free(lines);
            } else {
                printf("  暂无审计报告\n");
            }
            break;
        }
        case 6:
            color_yellow();
            printf("\n>>> [6] 小鸡资源展示 (未实现/TODO)\n");
            color_reset();
            break;
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
        case 10:
            color_yellow();
            printf("\n>>> [10] 断点续连 (未实现/TODO)\n");
            color_reset();
            break;
        case 11:
            saia_backpressure_menu();
            break;
        case 12:
            saia_telegram_menu();
            break;
        case 13: {
            char nodes_path[MAX_PATH_LENGTH];
            snprintf(nodes_path, sizeof(nodes_path), "%s/nodes.list", g_config.base_dir);
            color_cyan();
            printf(">>> [13] 更换IP列表\n");
            color_reset();
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
            char tokens_path[MAX_PATH_LENGTH];
            char mode_input[16];
            char next_input[16];
            int append_mode = 0;
            snprintf(tokens_path, sizeof(tokens_path), "%s/tokens.list", g_config.base_dir);
            color_cyan();
            printf("\n>>> [14] 更新 Tokens\n");
            color_reset();
            printf("[1] 覆盖现有\n");
            printf("[2] 追加到现有\n");
            printf("请选择 [1/2] (默认1): ");
            fflush(stdout);
            if (fgets(mode_input, sizeof(mode_input), stdin) && mode_input[0] == '2') {
                append_mode = 1;
            }

            while (g_running) {
                printf("请粘贴 token/user:pass（可多行/多次粘贴），完成后输入 EOF 结束。\n");
                int count = saia_write_list_file_from_input(tokens_path, 1, append_mode);
                if (count >= 0) {
                    color_green();
                    printf(">>> Tokens 已%s，本次写入 %d 条\n\n", append_mode ? "追加" : "覆盖", count);
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
            color_cyan();
            printf("\n>>> [17] 疑似无L7能力列表\n");
            color_reset();

            int found = 0;
            int has_any_report = 0;
            char report_path[MAX_PATH_LENGTH];
            for (int bi = 3; bi >= 0; bi--) {
                if (bi == 0) {
                    snprintf(report_path, sizeof(report_path), "%s/audit_report.log", g_config.base_dir);
                } else {
                    snprintf(report_path, sizeof(report_path), "%s/audit_report.log.%d", g_config.base_dir, bi);
                }

                char **lines = NULL;
                size_t lc = 0;
                if (file_read_lines(report_path, &lines, &lc) == 0 && lc > 0) {
                    has_any_report = 1;
                    for (size_t i = 0; i < lc; i++) {
                        if (!lines[i]) continue;
                        if (strstr(lines[i], "NO_L7") ||
                            strstr(lines[i], "无L7能力") ||
                            strstr(lines[i], "疑似无L7")) {
                            printf("  %s\n", lines[i]);
                            found++;
                        }
                    }

                    for (size_t i = 0; i < lc; i++) free(lines[i]);
                    free(lines);
                }
            }

            printf("\n总数: %d\n", found);
            if (!has_any_report) {
                color_yellow();
                printf("暂无审计报告\n");
                color_reset();
            } else if (found == 0) {
                color_yellow();
                printf("暂无疑似无L7数据\n");
                color_reset();
            }
            break;
        }
        case 18: {
            color_yellow();
            printf("\n>>> [18] 一键清理将停止审计并删除运行文件\n");
            printf("仅保留 IP/Tokens 等用户配置\n");
            color_reset();
            printf("确认执行? (y/N): ");
            fflush(stdout);

            char yn[8] = {0};
            if (fgets(yn, sizeof(yn), stdin) && (yn[0] == 'y' || yn[0] == 'Y')) {
                g_reload = 1;
                int removed = saia_cleanup_runtime_files(g_config.base_dir);
                color_green();
                printf(">>> 清理完成: 删除运行文件 %d 个\n", removed);
                color_reset();
            } else {
                color_dim();
                printf("已取消\n");
                color_reset();
            }
            break;
        }
        case 19: {
            color_yellow();
            printf("\n>>> [19] 初始化环境 (对齐 DEJI.py 逻辑)\n");
            printf("会停止审计并清理运行痕迹；默认保留 IP/Tokens 配置\n");
            color_reset();

            char input_keep_profile[8] = {0};
            char input_keep_ports[8] = {0};
            char confirm[8] = {0};

            printf("是否保留用户配置(IP/Tokens/通知配置)? (y/n, 默认y): ");
            fflush(stdout);
            fgets(input_keep_profile, sizeof(input_keep_profile), stdin);
            int keep_profile = !(input_keep_profile[0] == 'n' || input_keep_profile[0] == 'N');

            printf("是否保留端口配置? (y/n, 默认y): ");
            fflush(stdout);
            fgets(input_keep_ports, sizeof(input_keep_ports), stdin);
            int keep_ports = !(input_keep_ports[0] == 'n' || input_keep_ports[0] == 'N');

            printf("确认执行初始化? (y/N): ");
            fflush(stdout);
            fgets(confirm, sizeof(confirm), stdin);

            if (confirm[0] == 'y' || confirm[0] == 'Y') {
                g_reload = 1;
                int removed_runtime = saia_cleanup_runtime_files(g_config.base_dir);
                int removed_profile = 0;
                if (!keep_profile) {
                    removed_profile = saia_cleanup_profile_files(g_config.base_dir);
                }

                color_green();
                printf(">>> 初始化完成: 清理运行文件 %d 个, 清理配置 %d 个, 保留端口:%s\n",
                       removed_runtime, removed_profile, keep_ports ? "ON" : "OFF");
                color_reset();
            } else {
                color_dim();
                printf("已取消\n");
                color_reset();
            }
            break;
        }
        case 20:
            color_yellow();
            printf("\n>>> [20] 项目备注 (未实现/TODO)\n");
            color_reset();
            break;
        case 21:
            color_yellow();
            printf("\n>>> [21] IP 库管理 (未实现/TODO)\n");
            color_reset();
            break;
        default:
            color_red();
            printf("\n无效的选项: %d\n", choice);
            color_reset();
            break;
    } /* end switch */
    
    if (choice != 0) {
        printf("\n按回车键继续...");
        fflush(stdout);
        while (getchar() != '\n');
    }

    return 0;
} /* end main or menu fn wrapper */
