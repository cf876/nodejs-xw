#!/bin/bash
set -euo pipefail

# ================== 基础配置 ==================
ARGO_TOKEN=""
SINGLE_PORT_UDP="hy2"
HTTP_LOCAL_PORT=8082

# CF 优选域名列表
CF_DOMAINS=(
    "cf.090227.xyz"
    "cf.877774.xyz"
    "cf.130519.xyz"
    "cf.008500.xyz"
    "store.ubi.com"
    "saas.sin.fan"
)

# ================== 安装必要依赖 ==================
install_deps() {
    echo "[1/6] 安装基础依赖..."
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache openssl curl nodejs >/dev/null 2>&1 || true
    elif command -v apt >/dev/null 2>&1; then
        apt update >/dev/null 2>&1 && apt install -y openssl curl nodejs >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y openssl curl nodejs >/dev/null 2>&1 || true
    fi
    echo "[1/6] 依赖安装完成"
}

# ================== 基础信息获取 ==================
get_base_info() {
    echo "[2/6] 获取基础信息..."
    
    # 工作目录
    mkdir -p "$(dirname "$0")/.npm"
    cd "$(dirname "$0")"
    export FILE_PATH="${PWD}/.npm"
    rm -rf "$FILE_PATH" && mkdir -p "$FILE_PATH"
    
    # 公网IP
    PUBLIC_IP=$(curl -s --max-time 5 ipv4.ip.sb || curl -s --max-time 5 api.ipify.org || echo "127.0.0.1")
    if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" = "127.0.0.1" ]; then
        echo "[警告] 无法获取公网IP，使用本地回环地址"
    fi
    
    # CF优选域名
    select_cf_domain() {
        local available=()
        for domain in "${CF_DOMAINS[@]}"; do
            curl -s --max-time 2 -o /dev/null "https://$domain" && available+=("$domain")
        done
        [ ${#available[@]} -gt 0 ] && echo "${available[$((RANDOM % ${#available[@]}))]}" || echo "${CF_DOMAINS[0]}"
    }
    BEST_CF_DOMAIN=$(select_cf_domain)
    
    # 端口配置
    if [ -n "${SERVER_PORT:-}" ]; then
        PORTS_STRING="$SERVER_PORT"
    else
        PORTS_STRING="7860"
    fi
    read -ra AVAILABLE_PORTS <<< "$PORTS_STRING"
    
    PUBLIC_PORT=""
    TUIC_PORT=""
    HY2_PORT=""
    REALITY_PORT=""
    ARGO_PORT=8081
    HTTP_PORT=""
    
    if [ ${#AVAILABLE_PORTS[@]} -eq 1 ]; then
        PUBLIC_PORT=${AVAILABLE_PORTS[0]}
        TUIC_PORT=""
        HY2_PORT=$PUBLIC_PORT
        REALITY_PORT=$PUBLIC_PORT
        HTTP_PORT=$HTTP_LOCAL_PORT
    else
        TUIC_PORT=${AVAILABLE_PORTS[0]}
        HY2_PORT=${AVAILABLE_PORTS[1]}
        REALITY_PORT=${AVAILABLE_PORTS[0]}
        HTTP_PORT=${AVAILABLE_PORTS[1]}
    fi
    
    # UUID
    UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "fcef5ce2-116d-4929-97e9-b71989c46ff4")
    echo "$UUID" > "${FILE_PATH}/uuid.txt"
    
    echo "[2/6] 基础信息获取完成"
    echo "      公网IP: $PUBLIC_IP"
    echo "      工作端口: $PUBLIC_PORT"
}

# ================== 生成密钥和证书 ==================
generate_keys() {
    echo "[3/6] 生成密钥和证书..."
    
    # 下载sing-box和cloudflared
    ARCH=$(uname -m)
    [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && BASE_URL="https://arm64.ssss.nyc.mn" || BASE_URL="https://amd64.ssss.nyc.mn"
    [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && ARGO_ARCH="arm64" || ARGO_ARCH="amd64"
    
    # 创建目录并下载二进制文件（添加错误处理）
    mkdir -p "${FILE_PATH}"
    curl -L -sS --max-time 60 -o "${FILE_PATH}/sb" "${BASE_URL}/sb" && chmod +x "${FILE_PATH}/sb" >/dev/null 2>&1 || {
        echo "[错误] 下载sing-box失败"
        exit 0
    }
    curl -L -sS --max-time 60 -o "${FILE_PATH}/cloudflared" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARGO_ARCH}" && chmod +x "${FILE_PATH}/cloudflared" >/dev/null 2>&1 || {
        echo "[错误] 下载cloudflared失败"
        exit 0
    }
    
    # 生成Reality密钥
    KEY_OUTPUT=$("${FILE_PATH}/sb" generate reality-keypair 2>/dev/null)
    private_key=$(echo "$KEY_OUTPUT" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "$KEY_OUTPUT" | awk '/PublicKey:/ {print $2}')
    
    # 生成证书（静默）
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "${FILE_PATH}/private.key" -out "${FILE_PATH}/cert.pem" -days 3650 -subj "/CN=www.bing.com" >/dev/null 2>&1 || true
    
    echo "[3/6] 密钥和证书生成完成"
}

# ================== 生成sing-box配置 ==================
generate_config() {
    echo "[4/6] 生成服务配置..."
    
    # 构建入站配置
    INBOUNDS="{
        \"type\": \"hysteria2\",
        \"tag\": \"hy2-in\",
        \"listen\": \"::\",
        \"listen_port\": ${HY2_PORT},
        \"users\": [{\"password\": \"${UUID}\"}],
        \"tls\": {
            \"enabled\": true,
            \"alpn\": [\"h3\"],
            \"certificate_path\": \"${FILE_PATH}/cert.pem\",
            \"key_path\": \"${FILE_PATH}/private.key\"
        },
        \"log\": {\"level\": \"fatal\"}
    },{
        \"type\": \"vless\",
        \"tag\": \"vless-reality-in\",
        \"listen\": \"::\",
        \"listen_port\": ${REALITY_PORT},
        \"users\": [{\"uuid\": \"${UUID}\", \"flow\": \"xtls-rprx-vision\"}],
        \"tls\": {
            \"enabled\": true,
            \"server_name\": \"www.nazhumi.com\",
            \"reality\": {
                \"enabled\": true,
                \"handshake\": {\"server\": \"www.nazhumi.com\", \"server_port\": 443},
                \"private_key\": \"${private_key}\",
                \"short_id\": [\"\"]
            }
        },
        \"log\": {\"level\": \"fatal\"}
    },{
        \"type\": \"vless\",
        \"tag\": \"vless-argo-in\",
        \"listen\": \"127.0.0.1\",
        \"listen_port\": ${ARGO_PORT},
        \"users\": [{\"uuid\": \"${UUID}\"}],
        \"transport\": {
            \"type\": \"ws\",
            \"path\": \"/${UUID}-vless\"
        },
        \"log\": {\"level\": \"fatal\"}
    }"
    
    # 全局配置（仅fatal级别日志，无文件输出）
    cat > "${FILE_PATH}/config.json" <<CFGEOF
{
    "log": {
        "level": "fatal"
    },
    "inbounds": [${INBOUNDS}],
    "outbounds": [{"type": "direct", "tag": "direct"}]
}
CFGEOF

    echo "[4/6] 服务配置生成完成"
}

# ================== 启动服务 ==================
start_services() {
    echo "[5/6] 启动服务..."
    
    # 启动sing-box（所有输出丢弃，仅保留进程）
    nohup "${FILE_PATH}/sb" run -c "${FILE_PATH}/config.json" >/dev/null 2>&1 &
    SB_PID=$!
    sleep 2
    
    # 启动HTTP订阅服务（静默）
    cat > "${FILE_PATH}/server.js" <<JSEOF
const http = require('http');
const fs = require('fs');
http.createServer((req, res) => {
    if (req.url.includes('/sub')) {
        res.writeHead(200, {'Content-Type': 'text/plain; charset=utf-8'});
        try {
            res.end(fs.readFileSync('${FILE_PATH}/sub.txt', 'utf8'));
        } catch (e) {
            res.end('');
        }
    } else {
        res.writeHead(404);
        res.end('404');
    }
}).listen(${HTTP_PORT}, '0.0.0.0');
JSEOF
    nohup node "${FILE_PATH}/server.js" >/dev/null 2>&1 &
    HTTP_PID=$!
    
    # 启动Argo隧道（获取域名后丢弃输出）
    ARGO_LOG=$(mktemp)
    nohup "${FILE_PATH}/cloudflared" tunnel --edge-ip-version auto --protocol http2 --no-autoupdate --url http://127.0.0.1:${ARGO_PORT} >"$ARGO_LOG" 2>&1 &
    ARGO_PID=$!
    
    # 获取Argo域名
    ARGO_DOMAIN=""
    for i in {1..30}; do
        sleep 1
        ARGO_DOMAIN=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ARGO_LOG" | head -1 | sed 's|https://||')
        [ -n "$ARGO_DOMAIN" ] && break
    done
    rm -f "$ARGO_LOG"  # 删除临时日志
    
    # 保存PID信息
    echo "$SB_PID" > "${FILE_PATH}/sb.pid"
    echo "$HTTP_PID" > "${FILE_PATH}/http.pid"
    echo "$ARGO_PID" > "${FILE_PATH}/argo.pid"
    
    echo "[5/6] 服务启动完成"
    echo "      sing-box PID: $SB_PID"
    echo "      Argo 域名: ${ARGO_DOMAIN:-未获取}"
}

# ================== 生成节点信息 ==================
generate_nodes() {
    echo "[6/6] 生成节点信息..."
    
    # 构建节点链接
    > "${FILE_PATH}/list.txt"
    echo "hysteria2://${UUID}@${PUBLIC_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1#Hysteria2-Node" >> "${FILE_PATH}/list.txt"
    echo "vless://${UUID}@${PUBLIC_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&fp=chrome&pbk=${public_key}&type=tcp#Reality-Node" >> "${FILE_PATH}/list.txt"
    if [ -n "$ARGO_DOMAIN" ]; then
        echo "vless://${UUID}@${BEST_CF_DOMAIN}:443?encryption=none&security=tls&sni=${ARGO_DOMAIN}&type=ws&host=${ARGO_DOMAIN}&path=%2F${UUID}-vless#Argo-Node" >> "${FILE_PATH}/list.txt"
    fi
    
    # 生成订阅文件
    cat "${FILE_PATH}/list.txt" > "${FILE_PATH}/sub.txt"
    
    # 输出节点信息
    echo -e "\n==================================================="
    echo "🚀 节点信息（直接复制使用）"
    echo "==================================================="
    cat "${FILE_PATH}/list.txt"
    echo -e "==================================================="
    
    # 订阅链接
    if [ -n "$ARGO_DOMAIN" ]; then
        SUB_URL="http://${ARGO_DOMAIN}/sub"
    else
        SUB_URL="http://${PUBLIC_IP}:${HTTP_LOCAL_PORT}/sub (仅本地可访问)"
    fi
    echo -e "📦 订阅链接: $SUB_URL"
    echo -e "===================================================\n"
    
    echo "[6/6] 节点信息生成完成"
    echo -e "✅ 所有服务启动成功！\n"
}

# ================== 进程监控（可选）==================
monitor_process() {
    while true; do
        # 检查sing-box
        if [ -f "${FILE_PATH}/sb.pid" ]; then
            SB_PID=$(cat "${FILE_PATH}/sb.pid")
            if ! kill -0 $SB_PID 2>/dev/null; then
                echo "[监控] sing-box 异常退出，自动重启..."
                nohup "${FILE_PATH}/sb" run -c "${FILE_PATH}/config.json" >/dev/null 2>&1 &
                NEW_SB_PID=$!
                echo "$NEW_SB_PID" > "${FILE_PATH}/sb.pid"
                SB_PID=$NEW_SB_PID
            fi
        fi
        sleep 10
    done
}

# ================== 主程序 ==================
main() {
    clear
    echo "================================================"
    echo "          单端口多协议服务启动脚本"
    echo "================================================"
    
    # 捕获退出信号
    trap 'echo "脚本正常退出"; exit 0' SIGINT SIGTERM EXIT
    
    install_deps
    get_base_info
    generate_keys
    generate_config
    start_services
    generate_nodes
    
    # 启动后台监控（可选，注释掉则关闭）
    monitor_process >/dev/null 2>&1 &
    MONITOR_PID=$!
    echo "$MONITOR_PID" > "${FILE_PATH}/monitor.pid"
    
    # 保持脚本运行（容器友好方式）
    echo "服务已启动，保持运行中..."
    while true; do
        sleep 3600
    done
}

# 执行主程序
main