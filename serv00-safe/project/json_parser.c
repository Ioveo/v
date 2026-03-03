#include "saia.h"
#include <math.h>

// ==================== 工具函数 ====================

static const char *skip_whitespace(const char *json) {
    while (*json && (*json == ' ' || *json == '\t' || *json == '\n' || *json == '\r')) {
        json++;
    }
    return json;
}

static const char *parse_string(const char *json, char **out_str) {
    if (*json != '"') return NULL;
    json++; // Skip opening quote
    
    string_buffer_t *buf = string_buffer_create(256);
    if (!buf) return NULL;
    
    while (*json) {
        if (*json == '"') {
            json++; // Skip closing quote
            *out_str = string_buffer_to_string(buf);
            string_buffer_free(buf);
            return json;
        } else if (*json == '\\') {
            json++;
            if (!*json) break;
            char ch = *json;
            if (ch == 'b') string_buffer_append(buf, "\b");
            else if (ch == 'f') string_buffer_append(buf, "\f");
            else if (ch == 'n') string_buffer_append(buf, "\n");
            else if (ch == 'r') string_buffer_append(buf, "\r");
            else if (ch == 't') string_buffer_append(buf, "\t");
            else if (ch == 'u') {
                // Unicode handling simplified (skip)
                json += 4;
            } else {
                char tmp[2] = {ch, 0};
                string_buffer_append(buf, tmp);
            }
            json++;
        } else {
            char tmp[2] = {*json, 0};
            string_buffer_append(buf, tmp);
            json++;
        }
    }
    
    string_buffer_free(buf);
    return NULL;
}

static const char *parse_number(const char *json, double *out_num) {
    char *endptr;
    *out_num = strtod(json, &endptr);
    return (json == endptr) ? NULL : endptr;
}

static const char *parse_value(const char *json, json_node_t **out_node);

static const char *parse_array(const char *json, json_node_t **out_node) {
    json_node_t *node = json_create_array();
    json++; // Skip '['
    
    json = skip_whitespace(json);
    if (*json == ']') {
        *out_node = node;
        return json + 1;
    }
    
    while (*json) {
        json_node_t *val = NULL;
        json = parse_value(json, &val);
        if (!json) {
            json_free(node);
            return NULL;
        }
        json_array_append(node, val);
        
        json = skip_whitespace(json);
        if (*json == ']') {
            *out_node = node;
            return json + 1;
        } else if (*json == ',') {
            json++;
            json = skip_whitespace(json);
        } else {
            json_free(node);
            return NULL;
        }
    }
    json_free(node);
    return NULL;
}

static const char *parse_object(const char *json, json_node_t **out_node) {
    json_node_t *node = json_create_object();
    json++; // Skip '{'
    
    json = skip_whitespace(json);
    if (*json == '}') {
        *out_node = node;
        return json + 1;
    }
    
    while (*json) {
        char *key = NULL;
        json = parse_string(json, &key);
        if (!json || !key) {
            json_free(node);
            return NULL;
        }
        
        json = skip_whitespace(json);
        if (*json != ':') {
            free(key);
            json_free(node);
            return NULL;
        }
        json++; // Skip ':'
        json = skip_whitespace(json);
        
        json_node_t *val = NULL;
        json = parse_value(json, &val);
        if (!json) {
            free(key);
            json_free(node);
            return NULL;
        }
        
        json_object_set(node, key, val);
        free(key); // json_object_set duplicates the key
        
        json = skip_whitespace(json);
        if (*json == '}') {
            *out_node = node;
            return json + 1;
        } else if (*json == ',') {
            json++;
            json = skip_whitespace(json);
        } else {
            json_free(node);
            return NULL;
        }
    }
    json_free(node);
    return NULL;
}

static const char *parse_value(const char *json, json_node_t **out_node) {
    json = skip_whitespace(json);
    if (!*json) return NULL;
    
    if (*json == '{') {
        return parse_object(json, out_node);
    } else if (*json == '[') {
        return parse_array(json, out_node);
    } else if (*json == '"') {
        char *str = NULL;
        json = parse_string(json, &str);
        if (json) *out_node = json_create_string(str);
        if (str) free(str);
        return json;
    } else if (*json == 't' && strncmp(json, "true", 4) == 0) {
        *out_node = json_create_bool(1);
        return json + 4;
    } else if (*json == 'f' && strncmp(json, "false", 5) == 0) {
        *out_node = json_create_bool(0);
        return json + 5;
    } else if (*json == 'n' && strncmp(json, "null", 4) == 0) {
        *out_node = json_create_null();
        return json + 4;
    } else {
        double num;
        const char *new_json = parse_number(json, &num);
        if (new_json) {
            *out_node = json_create_number(num);
            return new_json;
        }
    }
    return NULL;
}

// ==================== 公共API ====================

json_node_t* json_parse(const char *json_str) {
    if (!json_str) return NULL;
    json_node_t *root = NULL;
    parse_value(json_str, &root);
    return root;
}

// ==================== JSON节点创建 ====================

json_node_t* json_create_null(void) {
    json_node_t *node = (json_node_t *)calloc(1, sizeof(json_node_t));
    if (node) {
        node->type = JSON_NULL;
    }
    return node;
}

json_node_t* json_create_bool(int value) {
    json_node_t *node = (json_node_t *)calloc(1, sizeof(json_node_t));
    if (node) {
        node->type = JSON_BOOL;
        node->value.boolean = value ? 1 : 0;
    }
    return node;
}

json_node_t* json_create_number(double value) {
    json_node_t *node = (json_node_t *)calloc(1, sizeof(json_node_t));
    if (node) {
        node->type = JSON_NUMBER;
        node->value.number = value;
    }
    return node;
}

json_node_t* json_create_string(const char *value) {
    json_node_t *node = (json_node_t *)calloc(1, sizeof(json_node_t));
    if (node) {
        node->type = JSON_STRING;
        if (value) {
            node->value.string = strdup(value);
        }
    }
    return node;
}

json_node_t* json_create_array(void) {
    json_node_t *node = (json_node_t *)calloc(1, sizeof(json_node_t));
    if (node) {
        node->type = JSON_ARRAY;
        node->value.array.items = NULL;
        node->value.array.count = 0;
        node->value.array.capacity = 0;
    }
    return node;
}

json_node_t* json_create_object(void) {
    json_node_t *node = (json_node_t *)calloc(1, sizeof(json_node_t));
    if (node) {
        node->type = JSON_OBJECT;
        node->value.object.keys = NULL;
        node->value.object.values = NULL;
        node->value.object.count = 0;
        node->value.object.capacity = 0;
    }
    return node;
}

// ==================== JSON数组操作 ====================

int json_array_append(json_node_t *array, json_node_t *value) {
    if (!array || array->type != JSON_ARRAY || !value) {
        return -1;
    }
    
    if (array->value.array.count >= array->value.array.capacity) {
        size_t new_capacity = array->value.array.capacity == 0 ? 16 : 
                              array->value.array.capacity * 2;
        json_node_t **new_items = (json_node_t **)realloc(
            array->value.array.items, 
            new_capacity * sizeof(json_node_t *)
        );
        if (!new_items) return -1;
        
        array->value.array.items = new_items;
        array->value.array.capacity = new_capacity;
    }
    
    array->value.array.items[array->value.array.count++] = value;
    return 0;
}

// ==================== JSON对象操作 ====================

int json_object_set(json_node_t *obj, const char *key, json_node_t *value) {
    if (!obj || obj->type != JSON_OBJECT || !key || !value) {
        return -1;
    }
    
    // 检查是否已存在
    for (size_t i = 0; i < obj->value.object.count; i++) {
        if (strcmp(obj->value.object.keys[i], key) == 0) {
            json_free(obj->value.object.values[i]);
            obj->value.object.values[i] = value;
            return 0;
        }
    }
    
    // 添加新键值对
    if (obj->value.object.count >= obj->value.object.capacity) {
        size_t new_capacity = obj->value.object.capacity == 0 ? 16 :
                              obj->value.object.capacity * 2;
        
        char **new_keys = (char **)realloc(
            obj->value.object.keys,
            new_capacity * sizeof(char *)
        );
        json_node_t **new_values = (json_node_t **)realloc(
            obj->value.object.values,
            new_capacity * sizeof(json_node_t *)
        );
        
        if (!new_keys || !new_values) return -1;
        
        obj->value.object.keys = new_keys;
        obj->value.object.values = new_values;
        obj->value.object.capacity = new_capacity;
    }
    
    obj->value.object.keys[obj->value.object.count] = strdup(key);
    obj->value.object.values[obj->value.object.count] = value;
    obj->value.object.count++;
    
    return 0;
}

// ==================== JSON释放 ====================

void json_free(json_node_t *node) {
    if (!node) return;
    
    switch (node->type) {
        case JSON_STRING:
            if (node->value.string) {
                free(node->value.string);
            }
            break;
            
        case JSON_ARRAY:
            for (size_t i = 0; i < node->value.array.count; i++) {
                json_free(node->value.array.items[i]);
            }
            if (node->value.array.items) {
                free(node->value.array.items);
            }
            break;
            
        case JSON_OBJECT:
            for (size_t i = 0; i < node->value.object.count; i++) {
                free(node->value.object.keys[i]);
                json_free(node->value.object.values[i]);
            }
            if (node->value.object.keys) {
                free(node->value.object.keys);
            }
            if (node->value.object.values) {
                free(node->value.object.values);
            }
            break;
            
        case JSON_NULL:
        case JSON_BOOL:
        case JSON_NUMBER:
            // 不需要释放
            break;
    }
    
    free(node);
}

// ==================== JSON值获取 ====================

json_node_t* json_get(json_node_t *node, const char *path) {
    if (!node || !path) return NULL;
    
    // 查找第一个 '.'
    const char *dot = strchr(path, '.');
    size_t key_len = dot ? (size_t)(dot - path) : strlen(path);
    char key[256];
    
    if (key_len >= sizeof(key)) return NULL;
    memcpy(key, path, key_len);
    key[key_len] = '\0';
    
    json_node_t *result = NULL;
    
    if (node->type == JSON_OBJECT) {
        for (size_t i = 0; i < node->value.object.count; i++) {
            if (strcmp(node->value.object.keys[i], key) == 0) {
                result = node->value.object.values[i];
                break;
            }
        }
    } else if (node->type == JSON_ARRAY && key_len > 0) {
        // 尝试解析为索引
        char *endptr;
        long idx = strtol(key, &endptr, 10);
        if (*endptr == '\0' && idx >= 0 && idx < (long)node->value.array.count) {
            result = node->value.array.items[idx];
        }
    }
    
    if (result && dot && *(dot + 1)) {
        return json_get(result, dot + 1);
    }
    
    return result;
}

json_type_t json_get_type(json_node_t *node) {
    return node ? node->type : JSON_NULL;
}

int json_get_bool(json_node_t *node, int default_val) {
    if (!node) return default_val;
    if (node->type == JSON_BOOL) return node->value.boolean;
    if (node->type == JSON_NUMBER) return (node->value.number != 0);
    if (node->type == JSON_STRING && node->value.string) {
        return (strcmp(node->value.string, "true") == 0 ||
                strcmp(node->value.string, "1") == 0);
    }
    return default_val;
}

double json_get_number(json_node_t *node, double default_val) {
    if (!node) return default_val;
    if (node->type == JSON_NUMBER) return node->value.number;
    if (node->type == JSON_STRING && node->value.string) {
        char *endptr;
        double val = strtod(node->value.string, &endptr);
        if (*endptr == '\0') return val;
    }
    if (node->type == JSON_BOOL) return node->value.boolean ? 1.0 : 0.0;
    return default_val;
}

char* json_get_string(json_node_t *node) {
    if (!node) return NULL;
    
    static char buffer[256];
    buffer[0] = '\0';
    
    switch (node->type) {
        case JSON_STRING:
            return node->value.string;
            
        case JSON_BOOL:
            snprintf(buffer, sizeof(buffer), "%s", node->value.boolean ? "true" : "false");
            return buffer;
            
        case JSON_NUMBER:
            if (node->value.number == floor(node->value.number)) {
                snprintf(buffer, sizeof(buffer), "%.0f", node->value.number);
            } else {
                snprintf(buffer, sizeof(buffer), "%g", node->value.number);
            }
            return buffer;
            
        case JSON_NULL:
            strcpy(buffer, "null");
            return buffer;
            
        default:
            return NULL;
    }
}

// ==================== JSON序列化 ====================

static void json_serialize_to_buffer(json_node_t *node, string_buffer_t *buf, int pretty, int indent);

static void json_indent(string_buffer_t *buf, int indent) {
    if (indent > 0) {
        for (int i = 0; i < indent; i++) {
            string_buffer_append(buf, "  ");
        }
    }
}

static void escape_json_string(const char *str, string_buffer_t *buf) {
    if (!str) {
        string_buffer_append(buf, "");
        return;
    }
    
    string_buffer_append(buf, "\"");
    for (size_t i = 0; str[i]; i++) {
        switch (str[i]) {
            case '"':
                string_buffer_append(buf, "\\\"");
                break;
            case '\\':
                string_buffer_append(buf, "\\\\");
                break;
            case '\b':
                string_buffer_append(buf, "\\b");
                break;
            case '\f':
                string_buffer_append(buf, "\\f");
                break;
            case '\n':
                string_buffer_append(buf, "\\n");
                break;
            case '\r':
                string_buffer_append(buf, "\\r");
                break;
            case '\t':
                string_buffer_append(buf, "\\t");
                break;
            default:
                if ((unsigned char)str[i] < 32) {
                    char escape[8];
                    snprintf(escape, sizeof(escape), "\\u%04x", (unsigned char)str[i]);
                    string_buffer_append(buf, escape);
                } else {
                    char ch[2] = {str[i], '\0'};
                    string_buffer_append(buf, ch);
                }
        }
    }
    string_buffer_append(buf, "\"");
}

static void json_serialize_value(json_node_t *node, string_buffer_t *buf, int pretty, int indent) {
    switch (node->type) {
        case JSON_NULL:
            string_buffer_append(buf, "null");
            break;
            
        case JSON_BOOL:
            string_buffer_append(buf, node->value.boolean ? "true" : "false");
            break;
            
        case JSON_NUMBER:
            if (node->value.number == floor(node->value.number)) {
                string_buffer_appendf(buf, "%.0f", node->value.number);
            } else {
                string_buffer_appendf(buf, "%g", node->value.number);
            }
            break;
            
        case JSON_STRING:
            escape_json_string(node->value.string, buf);
            break;
            
        case JSON_ARRAY:
            json_serialize_to_buffer(node, buf, pretty, indent);
            break;
            
        case JSON_OBJECT:
            json_serialize_to_buffer(node, buf, pretty, indent);
            break;
    }
}

static void json_serialize_to_buffer(json_node_t *node, string_buffer_t *buf, int pretty, int indent) {
    if (!node || !buf) return;
    
    if (node->type == JSON_ARRAY) {
        string_buffer_append(buf, "[");
        
        for (size_t i = 0; i < node->value.array.count; i++) {
            if (pretty) {
                string_buffer_append(buf, "\n");
                json_indent(buf, indent + 1);
            }
            
            json_serialize_value(node->value.array.items[i], buf, pretty, indent + 1);
            
            if (i < node->value.array.count - 1) {
                string_buffer_append(buf, ",");
            }
        }
        
        if (pretty && node->value.array.count > 0) {
            string_buffer_append(buf, "\n");
            json_indent(buf, indent);
        }
        
        string_buffer_append(buf, "]");
        
    } else if (node->type == JSON_OBJECT) {
        string_buffer_append(buf, "{");
        
        for (size_t i = 0; i < node->value.object.count; i++) {
            if (pretty) {
                string_buffer_append(buf, "\n");
                json_indent(buf, indent + 1);
            }
            
            escape_json_string(node->value.object.keys[i], buf);
            string_buffer_append(buf, ":");
            
            if (pretty) {
                string_buffer_append(buf, " ");
            }
            
            json_serialize_value(node->value.object.values[i], buf, pretty, indent + 1);
            
            if (i < node->value.object.count - 1) {
                string_buffer_append(buf, ",");
            }
        }
        
        if (pretty && node->value.object.count > 0) {
            string_buffer_append(buf, "\n");
            json_indent(buf, indent);
        }
        
        string_buffer_append(buf, "}");
    }
}

char* json_to_string(json_node_t *node, int pretty) {
    if (!node) return NULL;
    
    string_buffer_t *buf = string_buffer_create(4096);
    if (!buf) return NULL;
    
    json_serialize_value(node, buf, pretty, 0);
    
    char *result = string_buffer_to_string(buf);
    string_buffer_free(buf);
    return result;
}

// ==================== JSON文件操作 ====================

int json_save_to_file(json_node_t *node, const char *path, int pretty) {
    if (!node || !path) return -1;
    
    char *json_str = json_to_string(node, pretty);
    if (!json_str) return -1;
    
    int ret = file_write_all(path, json_str);
    free(json_str);
    
    return ret;
}

json_node_t* json_load_from_file(const char *path) {
    if (!path) return NULL;
    
    char *content = file_read_all(path);
    if (!content) return NULL;
    
    json_node_t *root = json_parse(content);
    free(content);
    
    return root;
}
