
#include "saia.h"

// ==================== 文件存在检查 ====================

int file_exists(const char *path) {
    if (!path) return 0;
#ifdef _WIN32
    DWORD attrs = GetFileAttributesA(path);
    return (attrs != INVALID_FILE_ATTRIBUTES && 
            !(attrs & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
#endif
}

// ==================== 目录存在检查 ====================

int dir_exists(const char *path) {
    if (!path) return 0;
#ifdef _WIN32
    DWORD attrs = GetFileAttributesA(path);
    return (attrs != INVALID_FILE_ATTRIBUTES && 
            (attrs & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
#endif
}

// ==================== 获取文件大小 ====================

size_t file_size(const char *path) {
    if (!path) return 0;
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA attrs;
    if (GetFileAttributesExA(path, GetFileExInfoStandard, &attrs)) {
        return ((size_t)attrs.nFileSizeHigh << 32) | attrs.nFileSizeLow;
    }
    return 0;
#else
    struct stat st;
    if (stat(path, &st) == 0) {
        return st.st_size;
    }
    return 0;
#endif
}

// ==================== 删除文件 ====================

int file_remove(const char *path) {
    if (!path) return -1;
#ifdef _WIN32
    return DeleteFileA(path) ? 0 : -1;
#else
    return unlink(path);
#endif
}

// ==================== 创建目录 ====================

int dir_create(const char *path) {
    if (!path) return -1;
#ifdef _WIN32
    return CreateDirectoryA(path, NULL) ? 0 : -1;
#else
    return mkdir(path, 0755);
#endif
}

// ==================== 读取所有内容 ====================

char* file_read_all(const char *path) {
    if (!path) return NULL;

    size_t size = file_size(path);
    if (size == 0) {
        // 可能是空文件或不存在
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    char *content = malloc(size + 1);
    if (!content) {
        fclose(fp);
        return NULL;
    }

    size_t read = fread(content, 1, size, fp);
    content[read] = '\0';
    fclose(fp);

    return content;
}

// ==================== 读取所有内容 (含大小) ====================

char* file_read_all_n(const char *path, size_t *size_out) {
    if (!path) {
        if (size_out) *size_out = 0;
        return NULL;
    }

    size_t size = file_size(path);
    if (size == 0) {
        if (size_out) *size_out = 0;
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        if (size_out) *size_out = 0;
        return NULL;
    }

    char *content = malloc(size + 1);
    if (!content) {
        fclose(fp);
        if (size_out) *size_out = 0;
        return NULL;
    }

    size_t read = fread(content, 1, size, fp);
    content[read] = '\0';
    fclose(fp);

    if (size_out) *size_out = read;
    return content;
}

// ==================== 写入全部内容 ====================

int file_write_all(const char *path, const char *content) {
    if (!path) return -1;

    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, fp);
    fclose(fp);

    return (written == len) ? 0 : -1;
}

// ==================== 追加内容 ====================

int file_append(const char *path, const char *text) {
    if (!path || !text) return -1;

    FILE *fp = fopen(path, "a");
    if (!fp) return -1;

    size_t len = strlen(text);
    size_t written = fwrite(text, 1, len, fp);
    fclose(fp);

    return (written == len) ? 0 : -1;
}

// ==================== 文件轮转 ====================

int file_rotate(const char *path, size_t max_size, int backup_count) {
    if (!path || backup_count <= 0) return 0;

    size_t size = file_size(path);
    if (size <= max_size) return 0;

    // 删除最老的备份
    char old_path[MAX_PATH_LENGTH];
    snprintf(old_path, sizeof(old_path), "%s.%d", path, backup_count);
    file_remove(old_path);

    // 重命名备份文件
    for (int i = backup_count - 1; i >= 1; i--) {
        char src[MAX_PATH_LENGTH];
        char dst[MAX_PATH_LENGTH];
        snprintf(src, sizeof(src), "%s.%d", path, i);
        snprintf(dst, sizeof(dst), "%s.%d", path, i + 1);
#ifdef _WIN32
        MoveFileA(src, dst);
#else
        rename(src, dst);
#endif
    }

    // 重命名原文件
    snprintf(old_path, sizeof(old_path), "%s.1", path);
#ifdef _WIN32
    MoveFileA(path, old_path);
#else
    rename(path, old_path);
#endif

    return 0;
}

// ==================== 追加并自动轮转 ====================

int file_append_rotate(const char *path, const char *text, size_t max_size, int backup_count) {
    if (!path || !text) return -1;

    // 先检查是否需要轮转
    if (file_exists(path)) {
        file_rotate(path, max_size, backup_count);
    }

    return file_append(path, text);
}

// ==================== 读取所有行 ====================

int file_read_lines(const char *path, char ***lines, size_t *count) {
    if (!path || !lines || !count) return -1;

    *lines = NULL;
    *count = 0;

    char *content = file_read_all(path);
    if (!content) {
        if (file_exists(path)) return -1;
        return 0;  // 文件不存在，返回空列表
    }

    // 计算行数
    size_t line_count = 0;
    for (size_t i = 0; content[i]; i++) {
        if (content[i] == '\n') line_count++;
    }
    if (strlen(content) > 0 && content[strlen(content)-1] != '\n') {
        line_count++;
    }

    // 分配数组
    *lines = (char **)malloc(line_count * sizeof(char *));
    if (!*lines) {
        free(content);
        return -1;
    }

    // 分割行
    char *line = content;
    size_t idx = 0;
    while (line && idx < line_count) {
        char *newline = strchr(line, '\n');
        if (newline) {
            *newline = '\0';
            // 去掉末尾的 \r (Windows CRLF)
            if (newline > line && *(newline - 1) == '\r') {
                *(newline - 1) = '\0';
            }
            (*lines)[idx] = strdup(line);
            line = newline + 1;
        } else {
            // 最后一行也去掉可能的 \r
            size_t ll = strlen(line);
            if (ll > 0 && line[ll - 1] == '\r') line[ll - 1] = '\0';
            (*lines)[idx] = strdup(line);
            line = NULL;
        }
        idx++;
    }

    *count = idx;
    free(content);

    return 0;
}

// ==================== 写入所有行 ====================

int file_write_lines(const char *path, char **lines, size_t count) {
    if (!path) return -1;

    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    for (size_t i = 0; i < count; i++) {
        if (lines[i]) {
            fprintf(fp, "%s\n", lines[i]);
        }
    }

    fclose(fp);
    return 0;
}
