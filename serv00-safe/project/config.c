#include "saia.h"

// 默认配置
static const char *default_xui_ports = "54321,2053,7777,5000";
static const char *default_s5_ports = "1080-1090,1111,2222,3333,4444,5555,6666,7777,8888,9999,1234,4321,8000,9000,10000-10010";
static const char *default_mixed_ports = NULL;  // 动态生成

// ==================== 配置初始化 ====================

int config_init(config_t *cfg, const char *base_dir) {
    if (!cfg || !base_dir) {
        return -1;
    }

    memset(cfg, 0, sizeof(config_t));

    // 基本配置
    strncpy(cfg->base_dir, base_dir, sizeof(cfg->base_dir) - 1);

    // 文件路径
    snprintf(cfg->state_file, sizeof(cfg->state_file), "%s/sys_audit_state.json",
             base_dir);
    snprintf(cfg->log_file, sizeof(cfg->log_file), "%s/sys_audit_events.log",
             base_dir);
    snprintf(cfg->report_file, sizeof(cfg->report_file), "%s/audit_report.log",
             base_dir);
    snprintf(cfg->nodes_file, sizeof(cfg->nodes_file), "%s/nodes.list",
             base_dir);
    snprintf(cfg->tokens_file, sizeof(cfg->tokens_file), "%s/tokens.list",
             base_dir);
    snprintf(cfg->ip_lib_file, sizeof(cfg->ip_lib_file), "%s/ip_lib.txt",
             base_dir);
    snprintf(cfg->telegram_config_file, sizeof(cfg->telegram_config_file),
             "%s/telegram_notify.json", base_dir);

    // 默认值
    cfg->mode = MODE_XUI;
    cfg->scan_mode = SCAN_EXPLORE_VERIFY;
    cfg->threads = 200;
    cfg->timeout = DEFAULT_TIMEOUT;
    cfg->feed_interval = 0.02f;
    cfg->feed_turbo_enabled = 1;
    cfg->expose_secret = 1;
    cfg->verbose = 0;
    cfg->resume_enabled = 1;
    cfg->skip_scanned = 0;

    // Telegram默认配置
    cfg->telegram_enabled = 0;
    cfg->telegram_token[0] = '\0';
    cfg->telegram_chat_id[0] = '\0';
    cfg->telegram_interval = 0;
    cfg->telegram_verified_threshold = 5;
    cfg->verify_source = 1;
    cfg->verify_filter = 1;

    // 压背控制默认配置
    cfg->backpressure.enabled = 0;
    cfg->backpressure.cpu_threshold = 80.0f;
    cfg->backpressure.mem_threshold = 2048.0f;
    cfg->backpressure.current_connections = 0;
    cfg->backpressure.max_connections = 200;
    cfg->backpressure.last_check = 0;
    cfg->backpressure.is_throttled = 0;
    cfg->backpressure.current_cpu = 0.0f;
    cfg->backpressure.current_mem = 0.0f;

    // 默认端口配置 (对应 DEJI.py DEFAULT_XUI_PORTS / DEFAULT_S5_PORTS)
    strncpy(cfg->xui_ports, DEFAULT_XUI_PORTS, sizeof(cfg->xui_ports) - 1);
    strncpy(cfg->s5_ports, DEFAULT_S5_PORTS, sizeof(cfg->s5_ports) - 1);
    strncpy(cfg->fofa_ports, DEFAULT_FOFA_TOP100_PORTS, sizeof(cfg->fofa_ports) - 1);

    // 尝试加载配置文件
    config_load(cfg, cfg->state_file);

    return 0;
}

// ==================== 解析端口配置 ====================

int config_parse_ports(const char *raw, uint16_t **ports, size_t *count) {
    if (!raw || !ports || !count) {
        return -1;
    }

    *ports = NULL;
    *count = 0;

    char *copy = strdup(raw);
    if (!copy) {
        return -1;
    }

    // 临时数组
    uint16_t temp_ports[MAX_PORTS];
    size_t temp_count = 0;

    char *token = strtok(copy, ",");
    while (token && temp_count < MAX_PORTS) {
        str_trim(token);
        if (strlen(token) == 0) {
            token = strtok(NULL, ",");
            continue;
        }

        // 检查是否是范围 (如 1080-1090)
        if (strchr(token, '-')) {
            char *dash = strchr(token, '-');
            *dash = '\0';
            char *start_str = token;
            char *end_str = dash + 1;
            str_trim(start_str);
            str_trim(end_str);

            uint16_t start = (uint16_t)atoi(start_str);
            uint16_t end = (uint16_t)atoi(end_str);

            if (start > end) {
                uint16_t tmp = start;
                start = end;
                end = tmp;
            }

            // 添加范围内的所有端口
            for (uint16_t p = start; p <= end && temp_count < MAX_PORTS; p++) {
                temp_ports[temp_count++] = p;
            }
        } else {
            // 单个端口
            uint16_t port = (uint16_t)atoi(token);
            if (port > 0 && port <= 65535) {
                temp_ports[temp_count++] = port;
            }
        }

        token = strtok(NULL, ",");
    }

    free(copy);

    // 分配内存并复制
    if (temp_count > 0) {
        *ports = (uint16_t *)malloc(temp_count * sizeof(uint16_t));
        if (!*ports) {
            return -1;
        }
        memcpy(*ports, temp_ports, temp_count * sizeof(uint16_t));
        *count = temp_count;
    }

    return 0;
}

// ==================== 设置默认端口 ====================

void config_set_default_ports(work_mode_t mode, uint16_t **ports, size_t *count) {
    const char *default_port_str = NULL;

    switch (mode) {
        case MODE_XUI:
            default_port_str = DEFAULT_XUI_PORTS;
            break;
        case MODE_S5:
            default_port_str = DEFAULT_S5_PORTS;
            break;
        case MODE_DEEP:
            default_port_str = DEFAULT_MIXED_PORTS;
            break;
        case MODE_VERIFY:
            default_port_str = DEFAULT_MIXED_PORTS;
            break;
        default:
            default_port_str = DEFAULT_MIXED_PORTS;
            break;
    }

    if (default_port_str) {
        config_parse_ports(default_port_str, ports, count);
    }
}

// ==================== 加载配置 ====================

int config_load(config_t *cfg, const char *path) {
    if (!cfg || !path) {
        return -1;
    }

    if (!file_exists(path)) {
        return 0;  // 文件不存在，使用默认配置
    }

    json_node_t *root = json_load_from_file(path);
    if (!root) {
        return -1;
    }

    // 读取配置
    json_node_t *node;

    int val;
    double dval;
    char *str;

    // 基本信息
    node = json_get(root, "mode");
    val = json_get_number(node, -1);
    if (val >= 1 && val <= 4) {
        cfg->mode = (work_mode_t)val;
    }

    node = json_get(root, "work_mode");
    val = json_get_number(node, -1);
    if (val >= 1 && val <= 3) {
        cfg->scan_mode = (scan_mode_t)val;
    }

    node = json_get(root, "threads");
    val = (int)json_get_number(node, -1);
    if (val > 0) {
        if (val < 1) val = 1;
        cfg->threads = val;
    }

    node = json_get(root, "timeout");
    val = (int)json_get_number(node, -1);
    if (val > 0) {
        cfg->timeout = val;
    }

    node = json_get(root, "feed_interval");
    dval = json_get_number(node, -1);
    if (dval > 0) {
        cfg->feed_interval = (float)dval;
    }

    node = json_get(root, "expose_secret");
    val = json_get_bool(node, -1);
    if (val >= 0) {
        cfg->expose_secret = (uint8_t)val;
    }

    node = json_get(root, "verbose");
    cfg->verbose = json_get_bool(node, 0);

    node = json_get(root, "resume_enabled");
    cfg->resume_enabled = json_get_bool(node, 1);

    node = json_get(root, "skip_scanned");
    cfg->skip_scanned = json_get_bool(node, 0);

    node = json_get(root, "verify_source");
    val = (int)json_get_number(node, 1);
    if (val >= 1 && val <= 2) cfg->verify_source = val;

    node = json_get(root, "verify_filter");
    val = (int)json_get_number(node, 1);
    if (val >= 1 && val <= 3) cfg->verify_filter = val;

    // 压背控制配置
    node = json_get(root, "backpressure");
    if (node && node->type == JSON_OBJECT) {
        json_node_t *bp_enabled = json_get(node, "enabled");
        if (bp_enabled) {
            cfg->backpressure.enabled = json_get_bool(bp_enabled, 0);
        }

        json_node_t *bp_cpu = json_get(node, "cpu_threshold");
        if (bp_cpu) {
            cfg->backpressure.cpu_threshold = (float)json_get_number(bp_cpu, 80.0);
        }

        json_node_t *bp_mem = json_get(node, "mem_threshold");
        if (bp_mem) {
            cfg->backpressure.mem_threshold = (float)json_get_number(bp_mem, 2048.0);
        }

        json_node_t *bp_max = json_get(node, "max_connections");
        if (bp_max) {
            cfg->backpressure.max_connections = (int)json_get_number(bp_max, 200);
        }
    }

    // Telegram配置
    node = json_get(root, "telegram");
    if (node && node->type == JSON_OBJECT) {
        json_node_t *tg_enabled = json_get(node, "enabled");
        if (tg_enabled) {
            cfg->telegram_enabled = json_get_bool(tg_enabled, 0);
        }

        json_node_t *tg_token = json_get(node, "bot_token");
        if (tg_token) {
            str = json_get_string(tg_token);
            if (str) {
                strncpy(cfg->telegram_token, str, sizeof(cfg->telegram_token) - 1);
            }
        }

        json_node_t *tg_chat = json_get(node, "chat_id");
        if (tg_chat) {
            str = json_get_string(tg_chat);
            if (str) {
                strncpy(cfg->telegram_chat_id, str, sizeof(cfg->telegram_chat_id) - 1);
            }
        }

        json_node_t *tg_interval = json_get(node, "interval_minutes");
        if (tg_interval) {
            cfg->telegram_interval = (int)json_get_number(tg_interval, 0);
        }

        json_node_t *tg_threshold = json_get(node, "verified_threshold");
        if (tg_threshold) {
            cfg->telegram_verified_threshold = (int)json_get_number(tg_threshold, 5);
        }
    }

    json_free(root);
    return 0;
}

// ==================== 保存配置 ====================

int config_save(const config_t *cfg, const char *path) {
    if (!cfg || !path) {
        return -1;
    }

    json_node_t *root = json_create_object();

    // 基本信息
    json_object_set(root, "mode", json_create_number(cfg->mode));
    json_object_set(root, "work_mode", json_create_number(cfg->scan_mode));
    json_object_set(root, "threads", json_create_number(cfg->threads));
    json_object_set(root, "timeout", json_create_number(cfg->timeout));
    json_object_set(root, "feed_interval", json_create_number(cfg->feed_interval));
    json_object_set(root, "expose_secret", json_create_bool(cfg->expose_secret));
    json_object_set(root, "verbose", json_create_bool(cfg->verbose));
    json_object_set(root, "resume_enabled", json_create_bool(cfg->resume_enabled));
    json_object_set(root, "skip_scanned", json_create_bool(cfg->skip_scanned));
    json_object_set(root, "verify_source", json_create_number(cfg->verify_source));
    json_object_set(root, "verify_filter", json_create_number(cfg->verify_filter));

    // 压背控制配置
    json_node_t *backpressure = json_create_object();
    json_object_set(backpressure, "enabled", json_create_bool(cfg->backpressure.enabled));
    json_object_set(backpressure, "cpu_threshold", json_create_number(cfg->backpressure.cpu_threshold));
    json_object_set(backpressure, "mem_threshold", json_create_number(cfg->backpressure.mem_threshold));
    json_object_set(backpressure, "max_connections", json_create_number(cfg->backpressure.max_connections));
    json_object_set(root, "backpressure", backpressure);

    // Telegram配置
    json_node_t *telegram = json_create_object();
    json_object_set(telegram, "enabled", json_create_bool(cfg->telegram_enabled));
    json_object_set(telegram, "bot_token", json_create_string(cfg->telegram_token));
    json_object_set(telegram, "chat_id", json_create_string(cfg->telegram_chat_id));
    json_object_set(telegram, "interval_minutes", json_create_number(cfg->telegram_interval));
    json_object_set(telegram, "verified_threshold", json_create_number(cfg->telegram_verified_threshold));
    json_object_set(root, "telegram", telegram);

    // 保存到文件
    int ret = json_save_to_file(root, path, 1);
    json_free(root);

    return ret;
}

// ==================== 打印配置 ====================

void config_print(const config_t *cfg) {
    if (!cfg) {
        return;
    }

    printf("当前配置:\n");
    printf("================================\n");
    printf("工作目录: %s\n", cfg->base_dir);
    printf("模式: %d\n", cfg->mode);
    printf("扫描模式: %d\n", cfg->scan_mode);
    printf("并发线程: %d\n", cfg->threads);
    printf("超时: %d 秒\n", cfg->timeout);
    printf("Feed间隔: %.3f\n", cfg->feed_interval);
    printf("暴露密钥: %s\n", cfg->expose_secret ? "是" : "否");
    printf("详细模式: %s\n", cfg->verbose ? "是" : "否");
    printf("恢复功能: %s\n", cfg->resume_enabled ? "是" : "否");
    printf("跳过已扫描: %s\n", cfg->skip_scanned ? "是" : "否");
    printf("\n");
    printf("压背控制:\n");
    printf("  启用: %s\n", cfg->backpressure.enabled ? "是" : "否");
    printf("  CPU阈值: %.1f%%\n", cfg->backpressure.cpu_threshold);
    printf("  内存阈值: %.1f MB\n", cfg->backpressure.mem_threshold);
    printf("  最大连接: %d\n", cfg->backpressure.max_connections);
    printf("\n");
    printf("Telegram:\n");
    printf("  启用: %s\n", cfg->telegram_enabled ? "是" : "否");
    if (cfg->telegram_enabled) {
        printf("  Bot Token: %s***\n", cfg->telegram_token);
        printf("  Chat ID: %s\n", cfg->telegram_chat_id);
        printf("  推送间隔: %d 分钟\n", cfg->telegram_interval);
    }
    printf("================================\n");
}
