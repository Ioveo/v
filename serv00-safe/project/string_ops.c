#include "saia.h"

// 简单的正则匹配（使用strstr作为简化实现）
int regex_match(const char *pattern, const char *str) {
    if (!pattern || !str) return 0;
    
    // 简化实现：如果模式不包含特殊字符，使用strstr
    if (strchr(pattern, '*') == NULL && 
        strchr(pattern, '?') == NULL && 
        strchr(pattern, '[') == NULL) {
        return strstr(str, pattern) != NULL;
    }
    
    // 通配符简单实现
    // 这里只是一个基础实现
    while (*pattern && *str) {
        if (*pattern == '*') {
            // *匹配任意序列
            pattern++;
            if (*pattern == '\0') return 1;
            while (*str) {
                if (regex_match(pattern, str++)) {
                    return 1;
                }
            }
            return 0;
        } else if (*pattern == '?') {
            // ?匹配任意单个字符
            pattern++;
            str++;
        } else if (*pattern == *str) {
            pattern++;
            str++;
        } else {
            return 0;
        }
    }
    
    if (*pattern == '\0' && *str == '\0') return 1;
    if (*pattern == '*' && *(pattern + 1) == '\0') return 1;
    
    return 0;
}

// 简化的正则提取
int regex_extract(const char *pattern, const char *str, char **matches, size_t *count) {
    if (!pattern || !str || !matches || !count) {
        return -1;
    }
    
    *matches = NULL;
    *count = 0;
    
    // 简化实现：提取模式中的变量
    // 这里只是一个占位符实现
    (void)pattern;
    (void)str;
    
    return -1;
}

// 解析凭据行
int parse_credentials(const char *line, credential_t *cred) {
    if (!line || !cred) return -1;
    
    memset(cred, 0, sizeof(credential_t));
    
    // 格式: username:password 或 password
    char *colon = strchr(line, ':');
    if (colon) {
        size_t user_len = colon - line;
        if (user_len > 0 && user_len < sizeof(cred->username)) {
            memcpy(cred->username, line, user_len);
            cred->username[user_len] = '\0';
        }
        
        const char *pass = colon + 1;
        size_t pass_len = strlen(pass);
        if (pass_len > 0 && pass_len < sizeof(cred->password)) {
            strncpy(cred->password, pass, sizeof(cred->password) - 1);
        }
    } else {
        // 只有密码，使用默认用户名
        strncpy(cred->password, line, sizeof(cred->password) - 1);
        strcpy(cred->username, "admin");
    }
    
    return 0;
}

// 解析多种格式的 IP/PORT/USER/PASS
int parse_ip_port_user_pass(const char *line, ip_port_t *addr, credential_t *cred) {
    if (!line || !addr || !cred) return -1;
    memset(addr, 0, sizeof(ip_port_t));
    memset(cred, 0, sizeof(credential_t));
    strcpy(cred->username, "-");
    strcpy(cred->password, "-");

    char buf[1024];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *s = str_trim(buf);

    /* 尝试解析 user:pass@ip:port 格式 */
    char *at = strchr(s, '@');
    if (at) {
        *at = '\0';
        char *up = s;
        char *ip_port_str = at + 1;
        char *colon_up = strchr(up, ':');
        if (colon_up) {
            *colon_up = '\0';
            strncpy(cred->username, up, sizeof(cred->username) - 1);
            strncpy(cred->password, colon_up + 1, sizeof(cred->password) - 1);
        } else {
            strncpy(cred->password, up, sizeof(cred->password) - 1);
            strcpy(cred->username, "admin");
        }
        
        char *colon_ip = strchr(ip_port_str, ':');
        if (colon_ip) {
            *colon_ip = '\0';
            ip_parse(ip_port_str, &addr->ip);
            addr->port = (uint16_t)atoi(colon_ip + 1);
        } else {
            ip_parse(ip_port_str, &addr->ip);
        }
        return 0;
    }

    /* 尝试解析 ip:port:user:pass 或 ip:user:pass 或 ip:port (使用全局/给定的凭据) */
    char *parts[4] = {0};
    int p_idx = 0;
    char *p = s;
    while (p_idx < 4 && p) {
        char *colon = strchr(p, ':');
        parts[p_idx++] = p;
        if (colon) {
            *colon = '\0';
            p = colon + 1;
        } else {
            p = NULL;
        }
    }

    if (p_idx >= 1) ip_parse(parts[0], &addr->ip);
    
    if (p_idx == 2) {
        /* ip:port 或者 ip:pass (罕见) */
        int val = atoi(parts[1]);
        if (val > 0 && val <= 65535) addr->port = (uint16_t)val;
        else strncpy(cred->password, parts[1], sizeof(cred->password) - 1);
    } else if (p_idx == 3) {
        /* ip:port:pass 或 ip:user:pass */
        int val = atoi(parts[1]);
        if (val > 0 && val <= 65535) {
            addr->port = (uint16_t)val;
            strncpy(cred->password, parts[2], sizeof(cred->password) - 1);
            strcpy(cred->username, "admin");
        } else {
            strncpy(cred->username, parts[1], sizeof(cred->username) - 1);
            strncpy(cred->password, parts[2], sizeof(cred->password) - 1);
        }
    } else if (p_idx >= 4) {
        /* ip:port:user:pass */
        addr->port = (uint16_t)atoi(parts[1]);
        strncpy(cred->username, parts[2], sizeof(cred->username) - 1);
        strncpy(cred->password, parts[3], sizeof(cred->password) - 1);
    }

    return 0;
}

// 提取国家和ASN信息
int extract_country_asn(const char *line, char *country, char *asn) {
    if (!line || !country || !asn) return -1;
    
    country[0] = '\0';
    asn[0] = '\0';
    
    // 查找国家代码 (2字母代码)
    const char *p = strstr(line, "|");
    while (p && *(p + 1)) {
        p++;
        
        // 跳过空格
        while (*p && (*p == ' ' || *p == '\t')) p++;
        
        // 检查是否是2字母国家代码
        if (isupper(*p) && isupper(*(p + 1)) && 
            (isspace(*(p + 2)) || *(p + 2) == '|' || *(p + 2) == '\0')) {
            country[0] = *p;
            country[1] = *(p + 1);
            country[2] = '\0';
            
            // 检查下一个是否是ASN
            const char *asn_start = p + 2;
            while (*asn_start && isspace(*asn_start)) asn_start++;
            
            if (strncasecmp(asn_start, "AS", 2) == 0) {
                const char *asn_end = asn_start + 2;
                while (*asn_end && isdigit(*asn_end)) asn_end++;
                size_t asn_len = asn_end - asn_start;
                if (asn_len < 32) {
                    strncpy(asn, asn_start, asn_len);
                    asn[asn_len] = '\0';
                }
            }
            
            return 0;
        }
        
        // 移动到下一个"|"
        p = strchr(p, '|');
    }
    
    // 尝试直接查找ASN
    const char *asn_pos = strstr(line, "AS");
    if (asn_pos) {
        const char *asn_end = asn_pos + 2;
        while (*asn_end && isdigit(*asn_end)) asn_end++;
        size_t asn_len = asn_end - asn_pos;
        if (asn_len >= 3 && asn_len < 32) {
            strncpy(asn, asn_pos, asn_len);
            asn[asn_len] = '\0';
        }
    }
    
    return 0;
}

// 提取RTT毫秒数
int extract_rtt_ms(const char *line) {
    if (!line) return -1;
    
    // 查找 "rtt:" 或 "RTT:"
    const char *patterns[] = {"rtt:", "RTT:", "rtt=", "RTT=", "rtt ", "RTT "};
    
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        const char *pos = strstr(line, patterns[i]);
        if (pos) {
            const char *val_start = pos + strlen(patterns[i]);
            while (*val_start && isspace(*val_start)) val_start++;
            
            char *endptr;
            long val = strtol(val_start, &endptr, 10);
            if (val > 0 && val < 60000) {  // 合理范围
                return (int)val;
            }
        }
    }
    
    return -1;
}

// ==================== IP 段/范围展开 ====================

/*
 * expand_ip_range: 将一行文本中的 IP 描述展开为独立 IP 字符串数组。
 * 支持格式:
 *   单 IP      1.2.3.4
 *   IP:PORT    1.2.3.4:8080   (后缀 :8080 会补充给展开项)
 *   CIDR       1.2.3.0/24   -> 1.2.3.1 ~ 1.2.3.254
 *   CIDR带端口 1.2.3.0/24:8080 -> 1.2.3.1:8080 ~ 1.2.3.254:8080
 *   范围(全)   1.2.3.1-1.2.3.254
 *   范围(末端) 1.2.3.1-254
 *
 * 参数: line   输入字符串
 *       out    *out 指向 malloc 分配的 char* 数组
 *       count  展开后的项数
 * 返回: 0=成功 -1=失败/无效
 * 调用方要 free(*out)[i] 和 free(*out) 本身
 */
int expand_ip_range(const char *line, char ***out, size_t *count) {
    if (!line || !out || !count) return -1;
    *out = NULL; *count = 0;

    char buf[1024];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    char *s = buf;
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    if (!*s || *s == '#') return -1;

    /* 寻找主 IP 段与后缀（比如 /24:8080 的 :8080， 或者 1.2.3.1-254 后的特殊字符）
     * 策略：从后往前找最后一个 ':'，由于 IPv6 本项目暂不重点支持，直接以最后冒号为准。
     * 并且后缀也可能是 username:password@这种放在前面的，但先分离尾部后缀。
     */
    char ip_part[512] = {0};
    char suffix[256] = "";
    strncpy(ip_part, s, sizeof(ip_part) - 1);
    
    // 寻找前缀 (例如 user:pass@)
    char prefix[256] = "";
    char *at = strchr(ip_part, '@');
    if (at) {
        size_t pref_len = at - ip_part + 1; // 包含 '@'
        if (pref_len < sizeof(prefix)) {
            strncpy(prefix, ip_part, pref_len);
            prefix[pref_len] = '\0';
        }
        // 将 ip_part 掐头
        memmove(ip_part, at + 1, strlen(at + 1) + 1);
    }

    // 定位可能是 port 相关的尾部冒号
    char *colon = NULL;
    char *slash = strchr(ip_part, '/');
    char *dash = strchr(ip_part, '-');
    
    if (slash) {
        colon = strchr(slash, ':');
    } else if (dash) {
        colon = strchr(dash, ':');
    } else {
        // 对于没有任何范围符号的单IP，比如 1.1.1.1:80，直接找最后一个冒号
        colon = strrchr(ip_part, ':');
    }

    if (colon) {
        strncpy(suffix, colon, sizeof(suffix) - 1);
        *colon = '\0';
    }

    uint32_t start_ip = 0, end_ip = 0;

#define IP_TO_U32(str, val) do { \
    struct in_addr _a; \
    if (inet_pton(AF_INET, (str), &_a) != 1) return -1; \
    (val) = ntohl(_a.s_addr); \
} while(0)

    slash = strchr(ip_part, '/');
    if (slash) {
        *slash = '\0';
        int pfx = atoi(slash + 1);
        if (pfx < 0 || pfx > 32) return -1;
        IP_TO_U32(ip_part, start_ip);
        uint32_t mask = pfx == 0 ? 0 : (~0u << (32 - pfx));
        start_ip = (start_ip & mask) + 1;
        end_ip   = (start_ip - 1) | (~mask & 0xFFFFFFFE);
        if (pfx >= 31) { start_ip = (start_ip & mask); end_ip = start_ip; }
        goto expand;
    }

    dash = strchr(ip_part, '-');
    if (dash) {
        *dash = '\0';
        const char *rhs = dash + 1;
        IP_TO_U32(ip_part, start_ip);
        if (strchr(rhs, '.')) {
            IP_TO_U32(rhs, end_ip);
        } else {
            int last = atoi(rhs);
            if (last < 0 || last > 255) return -1;
            end_ip = (start_ip & 0xFFFFFF00u) | (uint32_t)last;
        }
        if (end_ip < start_ip) { uint32_t t = start_ip; start_ip = end_ip; end_ip = t; }
        goto expand;
    }

    /* 单 IP */
    if (inet_pton(AF_INET, ip_part, &start_ip) != 1) {
        /* 如果 inet_pton 失败，它可能根本不是 IP (例如 username:password)，这直接返回-1就行 */
        return -1;
    }
    start_ip = ntohl(start_ip);
    end_ip = start_ip;

expand:;
    size_t n = (size_t)(end_ip - start_ip + 1);
    if (n == 0 || n > 16777216) return -1; /* 最多 /8 = 16M 个 IP, 对应 DEJI.py 无上限 */

    char **arr = (char **)malloc(n * sizeof(char *));
    if (!arr) return -1;

    for (size_t i = 0; i < n; i++) {
        uint32_t ip = start_ip + (uint32_t)i;
        struct in_addr a;
        a.s_addr = htonl(ip);
        char tmp[INET_ADDRSTRLEN + 512]; /* 加上 suffix 和 prefix 的余量 */
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
        
        snprintf(tmp, sizeof(tmp), "%s%s%s", prefix, ip_str, suffix);
        arr[i] = strdup(tmp);
        if (!arr[i]) {
            for (size_t j = 0; j < i; j++) free(arr[j]);
            free(arr);
            return -1;
        }
    }
    *out = arr;
    *count = n;
    return 0;
#undef IP_TO_U32
}

/*
 * expand_nodes_list: 读取节点文件中的每一行，展开 IP 段后合并为一个大数组。
 * 调用方对 (*expanded)[i] 和 (*expanded) 本身负责 free。
 */
int expand_nodes_list(char **raw_lines, size_t raw_count,
                      char ***expanded, size_t *exp_count) {
    if (!raw_lines || !expanded || !exp_count) return -1;
    *expanded = NULL; *exp_count = 0;

    /* 预估容量 */
    size_t cap = raw_count * 4 + 16;
    char **arr = (char **)malloc(cap * sizeof(char *));
    if (!arr) return -1;
    size_t total = 0;

    for (size_t li = 0; li < raw_count; li++) {
        const char *line = raw_lines[li];
        if (!line || !*line || *line == '#') continue;

        char **sub = NULL;
        size_t sub_n = 0;
        if (expand_ip_range(line, &sub, &sub_n) == 0 && sub && sub_n > 0) {
            /* 扩容 */
            if (total + sub_n >= cap) {
                cap = (total + sub_n) * 2 + 16;
                char **tmp = (char **)realloc(arr, cap * sizeof(char *));
                if (!tmp) {
                    for (size_t j = 0; j < sub_n; j++) free(sub[j]);
                    free(sub);
                    continue;
                }
                arr = tmp;
            }
            for (size_t si = 0; si < sub_n; si++) arr[total++] = sub[si];
            free(sub);
        } else {
            /* 如果解析失败（如带端口格式）直接保留原始行 */
            if (total + 1 >= cap) {
                cap = cap * 2 + 16;
                char **tmp = (char **)realloc(arr, cap * sizeof(char *));
                if (!tmp) continue;
                arr = tmp;
            }
            arr[total++] = strdup(line);
        }
    }

    *expanded = arr;
    *exp_count = total;
    return 0;
}

/* 快速估算 IP 段展开后的数目 — 纯数学计算，不分配任何内存 */
/* 对应 DEJI.py 的 estimate_expanded_target_count() */
size_t estimate_expanded_count(const char *raw) {
    if (!raw || !*raw) return 0;

    /* 跳过空白 */
    while (*raw && isspace((unsigned char)*raw)) raw++;
    size_t len = strlen(raw);
    if (len == 0) return 0;

    /* CIDR: x.x.x.x/N */
    const char *slash = strchr(raw, '/');
    if (slash) {
        int prefix = atoi(slash + 1);
        if (prefix >= 0 && prefix <= 32) {
            uint32_t host_bits = 32 - prefix;
            if (host_bits == 0) return 1;
            uint32_t n = (1U << host_bits);
            return (n > 2) ? (size_t)(n - 2) : (size_t)n; /* 去掉网络地址和广播 */
        }
    }

    /* 范围: x.x.x.A-B 或 x.x.x.A-y.y.y.B */
    const char *dash = strchr(raw, '-');
    if (dash) {
        const char *right = dash + 1;
        /* 短格式: 192.168.1.1-50 */
        int is_short = 1;
        for (const char *p = right; *p; p++) {
            if (!isdigit((unsigned char)*p)) { is_short = 0; break; }
        }
        if (is_short && strlen(right) <= 3) {
            /* 提取左边最后一段 */
            char left_copy[64];
            size_t dl = (size_t)(dash - raw);
            if (dl >= sizeof(left_copy)) dl = sizeof(left_copy) - 1;
            memcpy(left_copy, raw, dl);
            left_copy[dl] = '\0';
            char *last_dot = strrchr(left_copy, '.');
            if (last_dot) {
                int start_last = atoi(last_dot + 1);
                int end_last = atoi(right);
                if (end_last >= start_last && end_last <= 255) {
                    return (size_t)(end_last - start_last + 1);
                }
            }
        }
        /* 全 IP 范围: 1.2.3.4-5.6.7.8 */
        char left_ip[64], right_ip[64];
        size_t dl = (size_t)(dash - raw);
        if (dl < sizeof(left_ip)) {
            memcpy(left_ip, raw, dl);
            left_ip[dl] = '\0';
            strncpy(right_ip, right, sizeof(right_ip) - 1);
            right_ip[sizeof(right_ip) - 1] = '\0';
            struct in_addr a, b;
            if (inet_pton(AF_INET, left_ip, &a) == 1 && inet_pton(AF_INET, right_ip, &b) == 1) {
                uint32_t sa = ntohl(a.s_addr);
                uint32_t sb = ntohl(b.s_addr);
                if (sb >= sa) return (size_t)(sb - sa + 1);
            }
        }
    }

    return 1; /* 单个 IP */
}
