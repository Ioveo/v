#ifndef SAIA_H
#define SAIA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #include <ws2tcpip.h>
    #include <process.h>
    #include <conio.h>
    #include <io.h>
    #define SAIA_PATH_SEP '\\'
    #define saia_sleep(ms) Sleep(ms)
    #define __thread __declspec(thread)
    typedef int socklen_t;
    typedef int pid_t;
    #define close closesocket
    #define strcasecmp _stricmp
    #define strncasecmp _strnicmp
#else
    #include <unistd.h>
    #include <pthread.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <sys/select.h>
    #include <poll.h>
    #include <sys/time.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <strings.h> // for strcasecmp
    #define SAIA_PATH_SEP '/'
    #define saia_sleep(ms) usleep((ms) * 1000)
    #ifndef __thread
        #define __thread __thread
    #endif
#endif

// ==================== 常量定义 ====================

#define SAIA_VERSION "24.0"
#define SAIA_NAME "SYSTEM ASSET INTEGRITY AUDITOR"
#define MAX_PATH_LENGTH 4096
#define MAX_LINE_LENGTH 8192
#define MAX_URL_LENGTH 2048
#define MAX_PORTS 1000
#define MAX_THREADS 2000
#define DEFAULT_TIMEOUT 5
#define MAX_RETRY 3
#define BUFFER_SIZE 65536

// 文件大小限制
#define MAX_LOG_BYTES (2 * 1024 * 1024)
#define MAX_REPORT_BYTES (8 * 1024 * 1024)
#define MAX_STATE_BYTES (512 * 1024)

// 默认超时设置
#define SOCKET_TIMEOUT_SEC 5
#define CONNECT_TIMEOUT_MS 3000
#define READ_TIMEOUT_MS 5000

// 压背控制
#define DEFAULT_BACKPRESSURE_THRESHOLD 0.8
#define MIN_CONCURRENT_CONNECTIONS 50
#define MAX_CONCURRENT_CONNECTIONS 500
#define BACKPRESSURE_CHECK_INTERVAL 1

// ==================== 默认端口配置 ====================
// 对应 DEJI.py 原版端口默认值

#define DEFAULT_XUI_PORTS \
    "54321,2053,7777,5000"

#define DEFAULT_S5_PORTS \
    "1080-1090,1111,2222,3333,4444,5555,6666,7777,8888,9999," \
    "1234,4321,8000,9000,6868,6688,8866,9527,1472,2583,3694,10000-10010"

#define DEFAULT_S5_PORTS_HIGH \
    "1080-1085,10808-10810,2012,2080,4145,3128,10080,8080,8888,9999," \
    "1111,2222,3333,4444,5555,6666,7777,20000-20010,30000-30010,40000-40010," \
    "51234,65535,43892,11111,22222,33333"

#define DEFAULT_MIXED_PORTS \
    DEFAULT_XUI_PORTS "," DEFAULT_S5_PORTS

#define DEFAULT_FOFA_TOP100_PORTS \
    "80,81,82,83,88,89,90,95,96,98,99,100,101,102," \
    "1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090," \
    "1100,1111,1180,1200,1234,1314,1433,1521,1680,1880,1900," \
    "2000,2001,2002,2080,2082,2083,2086,2087,2095," \
    "3000,3001,3002,3128,3333," \
    "4000,4001,4002,4145,4321,4444," \
    "5000,5001,5432,5555,5601,5678,5683," \
    "6000,6001,6080,6379,6443,6666," \
    "7000,7001,7002,7003,7080,7443,7547,7777,7800," \
    "8000,8001,8008,8010,8080,8081,8082,8083,8086,8087,8088,8089,8090," \
    "8181,8443,8800,8880,8888," \
    "9000,9090,9443,10000"

// ==================== 颜色/样式 (极光配色) ====================
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_BLUE    "\033[38;5;39m"   /* 边框蓝 */
#define C_CYAN    "\033[38;5;51m"   /* 标题青 */
#define C_GREEN   "\033[38;5;46m"   /* 进度绿 */
#define C_YELLOW  "\033[38;5;214m"  /* 警告橙 */
#define C_RED     "\033[31m"
#define C_WHITE   "\033[97m"        /* 菜单白字 */
#define C_HOT     "\033[38;5;210m"  /* 菜单激活 (浅红) */

// ==================== 数据结构 ====================

// 字符串缓冲区
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} string_buffer_t;

// 动态数组
typedef struct {
    void **items;
    size_t size;
    size_t capacity;
} array_t;

// IP地址结构
typedef struct {
    char ip[64];       // IPv4或IPv6字符串
    int is_ipv6;
    // 简化处理，主要使用字符串形式
} ip_addr_t;

// IP端口对
typedef struct {
    ip_addr_t ip;
    uint16_t port;
} ip_port_t;

// 认证凭据
typedef struct {
    char username[4096];  // 扩展至 4K，支持长 token
    char password[4096];  // 扩展至 4K，支持长 token
} credential_t;

// 扫描目标
typedef struct {
    char target[256];          // 原始目标
    // 实际扫描时会动态生成任务
} scan_target_t;

// 扫描任务 (用于多线程)
typedef struct {
    ip_port_t addr;
    credential_t *creds;
    size_t cred_count;
    int type; // 0=TCP检测, 1=XUI, 2=SOCKS5
} scan_task_t;

// 扫描结果
typedef struct {
    ip_port_t addr;
    char service[64];          // 服务类型
    char status[32];           // 状态
    char banner[512];          // 标识
    time_t scan_time;
    int rtt_ms;
    credential_t cred;         // 成功凭据
    char country[8];           // 国家
    char asn[32];              // ASN
    int is_verified;
    int is_success;            // 1=成功
} scan_result_t;

// 工作模式
typedef enum {
    MODE_XUI = 1,
    MODE_S5 = 2,
    MODE_DEEP = 3,
    MODE_VERIFY = 4
} work_mode_t;

// 扫描模式
typedef enum {
    SCAN_EXPLORE = 1,
    SCAN_EXPLORE_VERIFY = 2,
    SCAN_PREMIUM_ONLY = 3
} scan_mode_t;

// 压背控制状态
typedef struct {
    bool enabled;
    float cpu_threshold;
    float mem_threshold;
    int current_connections;
    int max_connections;
    time_t last_check;
    bool is_throttled;
    float current_cpu;
    float current_mem;
} backpressure_state_t;

// 配置结构
typedef struct {
    work_mode_t mode;
    scan_mode_t scan_mode;
    int threads;
    int timeout;
    backpressure_state_t backpressure;
    float feed_interval;
    bool feed_turbo_enabled;
    char base_dir[MAX_PATH_LENGTH];
    char state_file[MAX_PATH_LENGTH];
    char log_file[MAX_PATH_LENGTH];
    char report_file[MAX_PATH_LENGTH];
    char nodes_file[MAX_PATH_LENGTH];
    char tokens_file[MAX_PATH_LENGTH];
    char ip_lib_file[MAX_PATH_LENGTH];
    char telegram_config_file[MAX_PATH_LENGTH];
    bool telegram_enabled;
    char telegram_token[512];
    char telegram_chat_id[128];
    int telegram_interval;
    int telegram_verified_threshold;
    int verify_source;   /* 1=stage1, 2=custom(13) */
    int verify_filter;   /* 1=all, 2=xui, 3=s5 */
    bool resume_enabled;
    bool skip_scanned;
    uint8_t expose_secret;
    bool verbose;
    /* 端口配置 (对应 DEJI.py DEFAULT_XUI_PORTS / DEFAULT_S5_PORTS) */
    char xui_ports[4096];
    char s5_ports[4096];
    char fofa_ports[4096];
} config_t;

// 状态结构
typedef struct {
    pid_t pid;
    int mode;
    int work_mode;
    int threads;
    char ports_raw[1024];
    float feed_interval;
    time_t start_time;
    time_t last_update;
    uint64_t total_scanned;
    uint64_t total_found;
    uint64_t total_verified;
    uint64_t xui_found;
    uint64_t xui_verified;
    uint64_t s5_found;
    uint64_t s5_verified;
    char status[32];
} state_t;

// JSON值类型
typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

// JSON节点
typedef struct json_node {
    json_type_t type;
    union {
        int boolean;
        double number;
        char *string;
        struct {
            struct json_node **items;
            size_t count;
            size_t capacity;
        } array;
        struct {
            char **keys;
            struct json_node **values;
            size_t count;
            size_t capacity;
        } object;
    } value;
} json_node_t;

// HTTP响应
typedef struct {
    int status_code;
    char *body;
    size_t body_len;
    char *headers;
} http_response_t;

// ==================== 全局变量 ====================

extern config_t g_config;
extern state_t g_state;
extern volatile sig_atomic_t g_running;
extern volatile sig_atomic_t g_reload;

// ==================== 函数声明 ====================

// main.c
int main(int argc, char *argv[]);
void saia_signal_handler(int signum);
void saia_cleanup(void);
void saia_print_banner(void);
int saia_run_audit(void);
int saia_print_menu(void);
int saia_run_audit_internal(int auto_mode, int auto_scan_mode, int auto_threads, int auto_port_batch_size);
int saia_config_menu(void);
int saia_report_menu(void);
int saia_nodes_menu(void);
int saia_interactive_mode(void);
int saia_realtime_monitor(void);
int saia_write_list_file_from_input(const char *file_path, int split_spaces, int append_mode);
int saia_doctor(void);
void saia_print_tokens_write_summary(const char *tokens_path, int append_mode, int written_count);
// missing_functions.c
int saia_backpressure_menu(void);
int saia_cleanup_menu(void);
int saia_telegram_menu(void);
int saia_credentials_menu(void);

// config.c
int config_init(config_t *cfg, const char *base_dir);
int config_load(config_t *cfg, const char *path);
int config_save(const config_t *cfg, const char *path);
void config_print(const config_t *cfg);
void config_set_default_ports(work_mode_t mode, uint16_t **ports, size_t *count);
int config_parse_ports(const char *raw, uint16_t **ports, size_t *count);

// file_ops.c
int file_read_lines(const char *path, char ***lines, size_t *count);
int file_write_lines(const char *path, char **lines, size_t count);
int file_append(const char *path, const char *text);
int file_rotate(const char *path, size_t max_size, int backup_count);
int file_append_rotate(const char *path, const char *text, size_t max_size, int backup_count);
int file_exists(const char *path);
int file_remove(const char *path);
size_t file_size(const char *path);
char* file_read_all(const char *path);
char* file_read_all_n(const char *path, size_t *size_out); /* 返回实际字节数 */

int file_write_all(const char *path, const char *content);
int dir_exists(const char *path);
int dir_create(const char *path);

// string_ops.c
int expand_ip_range(const char *line, char ***out, size_t *count);
size_t estimate_expanded_count(const char *raw);
int expand_nodes_list(char **raw_lines, size_t raw_count, char ***expanded, size_t *exp_count);
int parse_credentials(const char *line, credential_t *cred);
int parse_ip_port_user_pass(const char *line, ip_port_t *addr, credential_t *cred);


// network.c
int network_init(void);
void network_cleanup(void);
int socket_create(int ipv6);
int socket_connect_timeout(int fd, const struct sockaddr *addr, int addrlen, int timeout_ms);
int socket_set_nonblocking(int fd);
int socket_set_timeout(int fd, int sec);
int socket_send_all(int fd, const char *data, size_t len, int timeout_ms);
int socket_recv_until(int fd, char *buf, size_t size, const char *delimiter, int timeout_ms);
int socket_close(int fd);
int dns_resolve(const char *hostname, char *ip_buf, size_t size);
int ip_parse(const char *str, ip_addr_t *addr);
int ip_to_string(const ip_addr_t *addr, char *buf, size_t size);
int ip_is_valid(const char *str);

// http.c (新增)
http_response_t* http_get(const char *url, int timeout_ms);
http_response_t* http_post(const char *url, const char *data, int timeout_ms);
void http_response_free(http_response_t *res);
int http_parse_url(const char *url, char *host, int *port, char *path, int *ssl);
int send_telegram_message(const char *token, const char *chat_id, const char *text);
int push_telegram(const char *message);

// scanner.c
int scanner_init(void);
void scanner_cleanup(void);
// 核心扫描入口
void scanner_start_multithreaded(char **nodes, size_t node_count, credential_t *creds, size_t cred_count, uint16_t *ports, size_t port_count);
void scanner_start_streaming(const char *targets_file, credential_t *creds, size_t cred_count, uint16_t *ports, size_t port_count);
void scanner_send_completion_report(void);
void scanner_begin_completion_window(void);
// 单个验证函数
int verify_socks5(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms);
int verify_xui(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms);

// json_parser.c
json_node_t* json_parse(const char *json_str); // 需要实现
void json_free(json_node_t *node);
json_node_t* json_create_object(void);
json_node_t* json_create_array(void);
json_node_t* json_create_string(const char *value);
json_node_t* json_create_number(double value);
json_node_t* json_create_bool(int value);
json_node_t* json_create_null(void);
int json_object_set(json_node_t *obj, const char *key, json_node_t *value);
int json_array_append(json_node_t *array, json_node_t *value);
json_node_t* json_get(json_node_t *node, const char *path);
int json_get_bool(json_node_t *node, int default_val);
double json_get_number(json_node_t *node, double default_val);
char* json_get_string(json_node_t *node);
char* json_to_string(json_node_t *node, int pretty);
int json_save_to_file(json_node_t *node, const char *path, int pretty);
json_node_t* json_load_from_file(const char *path);

// utils.c
string_buffer_t* string_buffer_create(size_t initial_size);
void string_buffer_free(string_buffer_t *buf);
int string_buffer_append(string_buffer_t *buf, const char *str);
int string_buffer_appendf(string_buffer_t *buf, const char *fmt, ...);
char* string_buffer_to_string(string_buffer_t *buf);
char* str_trim(char *str);
char* str_lower(char *str);
char* str_upper(char *str);
char* str_replace(const char *src, const char *old, const char *replacement);
char* str_format(const char *fmt, ...);
char* str_join(char **items, size_t count, const char *separator);
char** str_split(const char *str, char delimiter, size_t *count);
int str_equals_ignore_case(const char *a, const char *b);
int str_contains(const char *haystack, const char *needle);
int str_starts_with(const char *str, const char *prefix);
int str_ends_with(const char *str, const char *suffix);
void get_current_time_str(char *buf, size_t size);
uint64_t get_current_time_ms(void);
int get_available_memory_mb(void);
int get_cpu_usage(void);
int get_hostname(char *buf, size_t size);
pid_t get_current_pid(void);
int is_process_alive(pid_t pid);
int stop_process(pid_t pid);

// color.c
void color_reset(void);
void color_bold(void);
void color_blue(void);
void color_cyan(void);
void color_green(void);
void color_yellow(void);
void color_red(void);
void color_magenta(void);
void color_white(void);
void color_dim(void);

// string_ops.c
int parse_credentials(const char *line, credential_t *cred);
int parse_ip_port_user_pass(const char *line, ip_port_t *addr, credential_t *cred);

// backpressure.c
int backpressure_init(backpressure_state_t *state);
void backpressure_update(backpressure_state_t *state);
int backpressure_should_throttle(backpressure_state_t *state);
void backpressure_adjust_connections(backpressure_state_t *state, int *current_conn);

#endif // SAIA_H
