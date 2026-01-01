#!/bin/bash
set -e

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

# ================== 安装必要依赖（修复：添加nodejs） ==================
install_deps() {
    echo "[1/6] 安装基础依赖..."
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache openssl curl nodejs >/dev/null 2>&1
    elif command -v apt >/dev/null 2>&1; then
        apt update >/dev/null 2>&1 && apt install -y openssl curl nodejs >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y openssl curl nodejs >/dev/null 2>&1
    fi
    echo "[1/6] 依赖安装完成"
}

# ================== 基础信息获取 ==================
get_base_info() {
    echo "[2/6] 获取基础信息..."
    
    # 工作目录
    cd "$(dirname "$0")"
    export FILE_PATH="${PWD}/.npm"
    rm -rf "$FILE_PATH" && mkdir -p "$FILE_PATH"
    
    # 公网IP（修复：增加多个备选地址）
    PUBLIC_IP=$(curl -s --max-time 5 ipv4.ip.sb || curl -s --max-time 5 api.ipify.org || curl -s --max-time 5 icanhazip.com)
    if [ -z "$PUBLIC_IP" ]; then
        echo "[错误] 无法获取公网IP" && exit 1
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
    [ -n "$SERVER_PORT" ] && PORTS_STRING="$SERVER_PORT" || PORTS_STRING="7860"
    read -ra AVAILABLE_PORTS <<< "$PORTS_STRING"
    if [ ${#AVAILABLE_PORTS[@]} -eq 1 ]; then
        PUBLIC_PORT=${AVAILABLE_PORTS[0]}
        TUIC_PORT=""
        HY2_PORT=$PUBLIC_PORT
        REALITY_PORT=$PUBLIC_PORT
        ARGO_PORT=8081
        HTTP_PORT=$HTTP_LOCAL_PORT
    else
        TUIC_PORT=${AVAILABLE_PORTS[0]}
        HY2_PORT=${AVAILABLE_PORTS[1]}
        REALITY_PORT=${AVAILABLE_PORTS[0]}
        HTTP_PORT=${AVAILABLE_PORTS[1]}
        ARGO_PORT=8081
    fi
    
    # UUID
    UUID=$(cat /proc/sys/kernel/random/uuid)
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
    
    # 修复：增加下载失败提示，确保文件可执行
    echo "正在下载sing-box..."
    if ! curl -L -sS --max-time 60 -o "${FILE_PATH}/sb" "${BASE_URL}/sb"; then
        echo "[错误] sing-box下载失败" && exit 1
    fi
    chmod +x "${FILE_PATH}/sb" || { echo "[错误] 无法设置执行权限"; exit 1; }
    
    echo "正在下载cloudflared..."
    if ! curl -L -sS --max-time 60 -o "${FILE_PATH}/cloudflared" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARGO_ARCH}"; then
        echo "[错误] cloudflared下载失败" && exit 1
    fi
    chmod +x "${FILE_PATH}/cloudflared" || { echo "[错误] 无法设置执行权限"; exit 1; }
    
    # 生成Reality密钥
    KEY_OUTPUT=$("${FILE_PATH}/sb" generate reality-keypair)
    private_key=$(echo "$KEY_OUTPUT" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "$KEY_OUTPUT" | awk '/PublicKey:/ {print $2}')
    
    # 生成证书（静默）
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "${FILE_PATH}/private.key" -out "${FILE_PATH}/cert.pem" -days 3650 -subj "/CN=www.bing.com" >/dev/null 2>&1
    
    echo "[3/6] 密钥和证书生成完成"
}

# ================== 生成sing-box配置（核心修复） ==================
generate_config() {
    echo "[4/6] 生成服务配置..."
    
    # 修复：监听地址改为0.0.0.0，确保容器外可访问
    INBOUNDS="{
        \"type\": \"hysteria2\",
        \"tag\": \"hy2-in\",
        \"listen\": \"0.0.0.0\",  # 修复：从::改为0.0.0.0
        \"listen_port\": ${HY2_PORT},
        \"users\": [{\"password\": \"${UUID}\"}],
        \"tls\": {
            \"enabled\": true,
            \"alpn\": [\"h3\"],
            \"certificate_path\": \"${FILE_PATH}/cert.pem\",
            \"key_path\": \"${FILE_PATH}/private.key\"
        },
        \"udp\": true,  # 修复：启用UDP支持
        \"log\": {\"level\": \"fatal\"}
    },{
        \"type\": \"vless\",
        \"tag\": \"vless-reality-in\",
        \"listen\": \"0.0.0.0\",  # 修复：从::改为0.0.0.0
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
        \"transport\": {\"type\": \"tcp\"},  # 修复：显式指定TCP传输
        \"log\": {\"level\": \"fatal\"}
    },{
        \"type\": \"vless\",
        \"tag\": \"vless-argo-in\",
        \"listen\": \"0.0.0.0\",  # 修复：从127.0.0.1改为0.0.0.0
        \"listen_port\": ${ARGO_PORT},
        \"users\": [{\"uuid\": \"${UUID}\"}],
        \"transport\": {
            \"type\": \"ws\",
            \"path\": \"/${UUID}-vless\"
        },
        \"log\": {\"level\": \"fatal\"}
    }"
    
    # 全局配置
    cat > "${FILE_PATH}/config.json" <<CFGEOF
{
    "log": {
        "level": "fatal"
    },
    "inbounds": [${INBOUNDS}],
    "outbounds": [{"type": "direct", "tag": "direct"}],
    "route": {
        "rules": [],
        "final": "direct"
    }
}
CFGEOF

    echo "[4/6] 服务配置生成完成"
}

# ================== 启动服务（修复） ==================
start_services() {
    echo "[5/6] 启动服务..."
    
    # 先停止可能存在的旧进程
    pkill -f "${FILE_PATH}/sb" >/dev/null 2>&1 || true
    pkill -f cloudflared >/dev/null 2>&1 || true
    pkill -f node.*server.js >/dev/null 2>&1 || true
    sleep 1
    
    # 启动sing-box
    nohup "${FILE_PATH}/sb" run -c "${FILE_PATH}/config.json" >"${FILE_PATH}/sb.log" 2>&1 &
    SB_PID=$!
    sleep 3  # 修复：延长等待时间
    
    # 检查sing-box是否启动成功
    if ! kill -0 $SB_PID 2>/dev/null; then
        echo "[错误] sing-box启动失败，日志："
        cat "${FILE_PATH}/sb.log"
        exit 1
    fi
    
    # 启动HTTP订阅服务（修复：绑定0.0.0.0）
    cat > "${FILE_PATH}/server.js" <<JSEOF
const http = require('http');
const fs = require('fs');
http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); // 修复：添加跨域支持
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
}).listen(${HTTP_PORT}, '0.0.0.0'); // 修复：从127.0.0.1改为0.0.0.0
JSEOF
    nohup node "${FILE_PATH}/server.js" >"${FILE_PATH}/http.log" 2>&1 &
    HTTP_PID=$!
    
    # 启动Argo隧道
    ARGO_LOG=$(mktemp)
    nohup "${FILE_PATH}/cloudflared" tunnel --edge-ip-version auto --protocol http2 --no-autoupdate --url http://0.0.0.0:${ARGO_PORT} >"$ARGO_LOG" 2>&1 &
    ARGO_PID=$!
    
    # 获取Argo域名
    ARGO_DOMAIN=""
    for i in {1..30}; do
        sleep 1
        ARGO_DOMAIN=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ARGO_LOG" | head -1 | sed 's|https://||')
        [ -n "$ARGO_DOMAIN" ] && break
    done
    rm -f "$ARGO_LOG"
    
    echo "[5/6] 服务启动完成"
    echo "      sing-box PID: $SB_PID"
    echo "      Argo 域名: ${ARGO_DOMAIN:-未获取}"
}

# ================== 生成节点信息 ==================
generate_nodes() {
    echo "[6/6] 生成节点信息..."
    
    # 构建节点链接（修复：修正参数格式）
    > "${FILE_PATH}/list.txt"
    # Hysteria2节点修复：添加必要参数
    echo "hysteria2://${UUID}@${PUBLIC_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1&alpn=h3#Hysteria2-Node" >> "${FILE_PATH}/list.txt"
    # Reality节点修复：补充完整参数
    echo "vless://${UUID}@${PUBLIC_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&fp=chrome&pbk=${public_key}&sid=&type=tcp#Reality-Node" >> "${FILE_PATH}/list.txt"
    if [ -n "$ARGO_DOMAIN" ]; then
        # Argo节点修复：修正WS参数
        echo "vless://${UUID}@${ARGO_DOMAIN}:443?encryption=none&security=tls&sni=${ARGO_DOMAIN}&type=ws&host=${ARGO_DOMAIN}&path=%2F${UUID}-vless&fp=chrome#Argo-Node" >> "${FILE_PATH}/list.txt"
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
        SUB_URL="http://${PUBLIC_IP}:${HTTP_LOCAL_PORT}/sub"
    fi
    echo -e "📦 订阅链接: $SUB_URL"
    echo -e "===================================================\n"
    
    echo "[6/6] 节点信息生成完成"
    echo -e "✅ 所有服务启动成功！\n"
}

# ================== 进程监控 ==================
monitor_process() {
    while true; do
        # 检查sing-box
        if ! kill -0 $SB_PID 2>/dev/null; then
            echo "[监控] sing-box 异常退出，自动重启..."
            nohup "${FILE_PATH}/sb" run -c "${FILE_PATH}/config.json" >"${FILE_PATH}/sb.log" 2>&1 &
            SB_PID=$!
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
    
    install_deps
    get_base_info
    generate_keys
    generate_config
    start_services
    generate_nodes
    
    # 启动后台监控
    monitor_process >/dev/null 2>&1 &
    
    # 保持脚本运行并返回0
    while true; do
        sleep 3600
    done
    exit 0
}

# 执行主程序
main