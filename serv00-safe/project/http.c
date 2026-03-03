#include "saia.h"

// ==================== URL解析 ====================

int http_parse_url(const char *url, char *host, int *port, char *path, int *ssl) {
    if (!url || !host || !port || !path || !ssl) return -1;
    
    char *p = (char *)url;
    *ssl = 0;
    *port = 80;
    
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    } else if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        *ssl = 1;
        *port = 443;
    }
    
    // 提取主机名
    char *slash = strchr(p, '/');
    char *colon = strchr(p, ':');
    
    size_t host_len = 0;
    if (colon && (!slash || colon < slash)) {
        host_len = colon - p;
        *port = atoi(colon + 1);
    } else if (slash) {
        host_len = slash - p;
    } else {
        host_len = strlen(p);
    }
    
    if (host_len >= 256) return -1;
    strncpy(host, p, host_len);
    host[host_len] = '\0';
    
    // 提取路径
    if (slash) {
        strncpy(path, slash, 1024 - 1);
        path[1023] = '\0';
    } else {
        strcpy(path, "/");
    }
    
    return 0;
}

// ==================== HTTP响应释放 ====================

void http_response_free(http_response_t *res) {
    if (!res) return;
    if (res->body) free(res->body);
    if (res->headers) free(res->headers);
    free(res);
}

// ==================== 使用系统CURL (HTTPS支持) ====================

static http_response_t* http_exec_curl(const char *method, const char *url, const char *data, int timeout_ms) {
    // 创建临时文件存储响应
    char tmp_header[MAX_PATH_LENGTH];
    char tmp_body[MAX_PATH_LENGTH];
    snprintf(tmp_header, sizeof(tmp_header), "saia_hdr_%d.tmp", get_current_pid());
    snprintf(tmp_body, sizeof(tmp_body), "saia_body_%d.tmp", get_current_pid());
    
    string_buffer_t *cmd = string_buffer_create(2048);
    string_buffer_appendf(cmd, "curl -s -X %s ", method);
    string_buffer_appendf(cmd, "--connect-timeout %d ", timeout_ms / 1000 > 0 ? timeout_ms / 1000 : 1);
    string_buffer_appendf(cmd, "-m %d ", timeout_ms / 1000 + 2); // 总超时
    string_buffer_appendf(cmd, "-D \"%s\" ", tmp_header);
    string_buffer_appendf(cmd, "-o \"%s\" ", tmp_body);
    
    // 禁用证书验证 (为了兼容性)
    string_buffer_append(cmd, "-k ");
    
    if (data) {
        // 简单处理引号转义
        string_buffer_append(cmd, "-d '");
        string_buffer_append(cmd, data); // 注意：这里可能存在注入风险，实际应更严谨
        string_buffer_append(cmd, "' ");
    }
    
    string_buffer_appendf(cmd, "\"%s\"", url);
    
    // 执行命令
    char *cmd_str = string_buffer_to_string(cmd);
    int ret = system(cmd_str);
    free(cmd_str);
    string_buffer_free(cmd);
    
    http_response_t *res = (http_response_t *)calloc(1, sizeof(http_response_t));
    if (ret != 0) {
        res->status_code = -1;
        file_remove(tmp_header);
        file_remove(tmp_body);
        return res;
    }
    
    // 读取Header获取状态码
    char *header_content = file_read_all(tmp_header);
    if (header_content) {
        res->headers = header_content;
        // 解析状态码: HTTP/1.1 200 OK
        char *space = strchr(header_content, ' ');
        if (space) {
            res->status_code = atoi(space + 1);
        }
    }
    
    // 读取Body
    char *body_content = file_read_all(tmp_body);
    if (body_content) {
        res->body = body_content;
        res->body_len = file_size(tmp_body);
    }
    
    file_remove(tmp_header);
    file_remove(tmp_body);
    
    return res;
}

// ==================== 原生HTTP请求 (仅HTTP) ====================

static http_response_t* http_socket_request(const char *method, const char *url, const char *data, int timeout_ms) {
    char host[256];
    int port;
    char path[1024];
    int ssl;
    
    if (http_parse_url(url, host, &port, path, &ssl) != 0) return NULL;
    
    // 如果是HTTPS，回退到curl
    if (ssl) {
        return http_exec_curl(method, url, data, timeout_ms);
    }
    
    // 解析IP
    char ip[64];
    if (dns_resolve(host, ip, sizeof(ip)) != 0) return NULL;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    int fd = socket_create(0, 1);
    if (fd < 0) return NULL;
    
    if (socket_connect_timeout(fd, (struct sockaddr*)&addr, sizeof(addr), timeout_ms) != 0) {
        socket_close(fd);
        return NULL;
    }
    
    // 构造请求
    string_buffer_t *req = string_buffer_create(1024);
    string_buffer_appendf(req, "%s %s HTTP/1.1\r\n", method, path);
    string_buffer_appendf(req, "Host: %s\r\n", host);
    string_buffer_append(req, "User-Agent: SAIA/24.0\r\n");
    string_buffer_append(req, "Connection: close\r\n");
    
    if (data) {
        string_buffer_appendf(req, "Content-Length: %zu\r\n", strlen(data));
        string_buffer_append(req, "Content-Type: application/x-www-form-urlencoded\r\n");
    }
    string_buffer_append(req, "\r\n");
    
    if (data) {
        string_buffer_append(req, data);
    }
    
    char *req_str = string_buffer_to_string(req);
    if (socket_send_all(fd, req_str, strlen(req_str), timeout_ms) < 0) {
        free(req_str);
        string_buffer_free(req);
        socket_close(fd);
        return NULL;
    }
    free(req_str);
    string_buffer_free(req);
    
    /* 读取响应 — 按实际字节数追加，避免响应体含 \0 被 strlen 截断 */
    string_buffer_t *resp_buf = string_buffer_create(8192);
    char chunk[4096];
    int n;
    while ((n = socket_recv_until(fd, chunk, sizeof(chunk), NULL, timeout_ms)) > 0) {
        string_buffer_append_len(resp_buf, chunk, (size_t)n);
    }
    
    socket_close(fd);
    
    http_response_t *res = (http_response_t *)calloc(1, sizeof(http_response_t));

    size_t raw_size = string_buffer_size(resp_buf);
    char *raw = string_buffer_to_string(resp_buf); /* malloc+memcpy */
    string_buffer_free(resp_buf);
    if (!raw) return res;

    
    /* 分离 Header 和 Body，按实际 raw_size 计算 body 长度 */
    char *body_sep = strstr(raw, "\r\n\r\n");
    if (body_sep) {
        *body_sep = '\0';
        res->headers = strdup(raw);
        char *body_start = body_sep + 4;
        size_t body_len = raw_size - (size_t)(body_start - raw);
        res->body = (char *)malloc(body_len + 1);
        if (res->body) {
            memcpy(res->body, body_start, body_len);
            res->body[body_len] = '\0';
            res->body_len = body_len;
        }
        /* 解析状态码 */
        char *sp = strchr(raw, ' ');
        if (sp) res->status_code = atoi(sp + 1);
    } else {
        /* 没有 header 分隔符，整体当 body */
        res->body = raw;
        res->body_len = raw_size;
        raw = NULL; /* 转让所有权，避免 double-free */
    }
    if (raw) free(raw);

    
    return res;
}

// ==================== 公共接口 ====================

http_response_t* http_get(const char *url, int timeout_ms) {
    return http_socket_request("GET", url, NULL, timeout_ms);
}

http_response_t* http_post(const char *url, const char *data, int timeout_ms) {
    return http_socket_request("POST", url, data, timeout_ms);
}

// ==================== Telegram 推送接口 ====================

int send_telegram_message(const char *token, const char *chat_id, const char *text) {
    if (!token || !chat_id || !text || strlen(token) == 0 || strlen(chat_id) == 0) return -1;
    
    char url[512];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage", token);
    
    // 构造请求数据 (假设我们直接使用 curl，也可以用 cJSON)
    // -F chat_id="..." -F text="..." -F parse_mode="html"
    string_buffer_t *cmd = string_buffer_create(2048);
    string_buffer_appendf(cmd, "curl -s -X POST \"%s\" ", url);
    string_buffer_appendf(cmd, "-F \"chat_id=%s\" ", chat_id);
    string_buffer_append(cmd, "-F \"parse_mode=html\" ");
    
    // 将 text 进行转义 (为了安全放在文件里供 curl 读取)
    char tmp_body[MAX_PATH_LENGTH];
    snprintf(tmp_body, sizeof(tmp_body), "tg_msg_%d.tmp", get_current_pid());
    file_write_all(tmp_body, text);
    
    string_buffer_appendf(cmd, "-F \"text=<%s\" ", tmp_body);
    
    char *cmd_str = string_buffer_to_string(cmd);
    int ret = system(cmd_str);
    free(cmd_str);
    string_buffer_free(cmd);
    file_remove(tmp_body);
    
    return ret == 0 ? 0 : -1;
}

int push_telegram(const char *message) {
    if (!g_config.telegram_enabled) return 0;
    return send_telegram_message(g_config.telegram_token, g_config.telegram_chat_id, message);
}
