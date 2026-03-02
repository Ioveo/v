
#include "saia.h"

int backpressure_init(backpressure_state_t *state) {
    if (!state) return -1;
    
    memset(state, 0, sizeof(backpressure_state_t));
    state->enabled = 1;
    state->cpu_threshold = DEFAULT_BACKPRESSURE_THRESHOLD * 100.0f;
    state->mem_threshold = 2048.0f;
    state->current_connections = 0;
    state->max_connections = MAX_CONCURRENT_CONNECTIONS;
    state->last_check = 0;
    state->is_throttled = 0;
    state->current_cpu = 0.0f;
    state->current_mem = (float)get_available_memory_mb();
    
    return 0;
}

void backpressure_update(backpressure_state_t *state) {
    if (!state || !state->enabled) return;
    
    time_t now = time(NULL);
    if (now - state->last_check < BACKPRESSURE_CHECK_INTERVAL) {
        return;
    }
    
    state->current_cpu = (float)get_cpu_usage();
    state->current_mem = (float)get_available_memory_mb();
    state->last_check = now;
    
    // 检查是否达到阈值
    // CPU 在容器/小鸡环境下口径不稳定，禁用 CPU 触发限流
    int cpu_high = 0;
    int mem_low = (state->current_mem < state->mem_threshold);
    
    // 内存使用 = 总内存 - 可用内存
    float mem_usage = 0.0f;
    #ifdef _WIN32
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    mem_usage = (float)(statex.ullTotalPhys - statex.ullAvailPhys) / (1024 * 1024);
    #endif
    
    if (mem_usage > state->mem_threshold) {
        mem_low = 1;
    }
    
    state->is_throttled = (cpu_high || mem_low);
    /* 注意: 不再把 current_connections > max_connections 作为限流判断,
     * 因为 scanner 本身已通过 running_threads < g_config.threads 控制 */
    
    // 自动调整最大连接数 — 温和调整，避免过度压缩
    int min_floor = g_config.threads / 2; /* 最低不能低于用户设定值的一半 */
    if (min_floor < MIN_CONCURRENT_CONNECTIONS) min_floor = MIN_CONCURRENT_CONNECTIONS;
    
    if (state->is_throttled && state->max_connections > min_floor) {
        state->max_connections -= 10; /* 每次只减少10，温和降级 */
        if (state->max_connections < min_floor) {
            state->max_connections = min_floor;
        }
    } else if (!state->is_throttled && state->max_connections < g_config.threads) {
        state->max_connections += 50; /* 快速恢复 */
        if (state->max_connections > g_config.threads) {
            state->max_connections = g_config.threads;
        }
    }
}

int backpressure_should_throttle(backpressure_state_t *state) {
    if (!state || !state->enabled) return 0;
    return state->is_throttled;
}

void backpressure_adjust_connections(backpressure_state_t *state, int *current_conn) {
    if (!state || !current_conn) return;
    
    if (*current_conn > state->max_connections) {
        *current_conn = state->max_connections;
    }
    
    state->current_connections = *current_conn;
}
