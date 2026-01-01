#!/bin/bash
set -e

# ================== 配置区域 ==================
# 固定隧道填写token，不填默认为临时隧道
ARGO_TOKEN=""

# 单端口模式 UDP 协议选择: hy2 (默认) 或 tuic
SINGLE_PORT_UDP="hy2"

# HTTP 订阅服务本地端口（避免占用公网端口）
HTTP_LOCAL_PORT=8082

# ================== CF 优选域名列表 ==================
CF_DOMAINS=(
    "cf.090227.xyz"
    "cf.877774.xyz"
    "cf.130519.xyz"
    "cf.008500.xyz"
    "store.ubi.com"
    "saas.sin.fan"
)

# ================== 新增：安装 OpenSSL (兼容 Alpine 系统) ==================
install_openssl() {
    echo "[依赖] 检查 OpenSSL 是否安装..."
    if command -v openssl >/dev/null 2>&1; then
        echo "[依赖] OpenSSL 已安装"
        return 0
    fi

    # 判断系统包管理器并安装
    if command -v apk >/dev/null 2>&1; then
        echo "[依赖] 使用 apk 安装 OpenSSL..."
        apk add --no-cache openssl
    elif command -v apt >/dev/null 2>&1; then
        echo "[依赖] 使用 apt 安装 OpenSSL..."
        apt update && apt install -y openssl
    elif command -v yum >/dev/null 2>&1; then
        echo "[依赖] 使用 yum 安装 OpenSSL..."
        yum install -y openssl
    else
        echo "[错误] 无法识别系统包管理器，手动安装 OpenSSL 后重试"
        exit 1
    fi

    # 验证安装结果
    if command -v openssl >/dev/null 2>&1; then
        echo "[依赖] OpenSSL 安装成功"
    else
        echo "[错误] OpenSSL 安装失败"
        exit 1
    fi
}

# 执行 OpenSSL 安装
install_openssl

# ================== 切换到脚本目录 ==================
cd "$(dirname "$0")"
export FILE_PATH="${PWD}/.npm"

rm -rf "$FILE_PATH"
mkdir -p "$FILE_PATH"

# ================== 获取公网 IP ==================
echo "[网络] 获取公网 IP..."
PUBLIC_IP=$(curl -s --max-time 5 ipv4.ip.sb || curl -s --max-time 5 api.ipify.org || echo "")
[ -z "$PUBLIC_IP" ] && echo "[错误] 无法获取公网 IP" && exit 1
echo "[网络] 公网 IP: $PUBLIC_IP"

# ================== CF 优选：随机选择可用域名 ==================
select_random_cf_domain() {
    local available=()
    for domain in "${CF_DOMAINS[@]}"; do
        if curl -s --max-time 2 -o /dev/null "https://$domain" 2>/dev/null; then
            available+=("$domain")
        fi
    done
    [ ${#available[@]} -gt 0 ] && echo "${available[$((RANDOM % ${#available[@]}))]}" || echo "${CF_DOMAINS[0]}"
}

echo "[CF优选] 测试中..."
BEST_CF_DOMAIN=$(select_random_cf_domain)
echo "[CF优选] $BEST_CF_DOMAIN"

# ================== 获取端口 ==================
[ -n "$SERVER_PORT" ] && PORTS_STRING="$SERVER_PORT" || PORTS_STRING="7860"
read -ra AVAILABLE_PORTS <<< "$PORTS_STRING"
PORT_COUNT=${#AVAILABLE_PORTS[@]}
[ $PORT_COUNT -eq 0 ] && echo "[错误] 未找到端口" && exit 1
echo "[端口] 发现 $PORT_COUNT 个: ${AVAILABLE_PORTS[*]}"

# ================== 端口分配逻辑【核心修复】==================
if [ $PORT_COUNT -eq 1 ]; then
    # 单端口模式：公网端口仅给 sing-box (UDP+TCP)，HTTP 用独立本地端口
    PUBLIC_PORT=${AVAILABLE_PORTS[0]}
    TUIC_PORT=""
    HY2_PORT=""
    [[ "$SINGLE_PORT_UDP" == "tuic" ]] && TUIC_PORT=$PUBLIC_PORT || HY2_PORT=$PUBLIC_PORT
    REALITY_PORT=$PUBLIC_PORT  # Reality(TCP) 与 UDP 共用公网端口
    ARGO_PORT=8081             # Argo WS 本地端口
    HTTP_PORT=$HTTP_LOCAL_PORT # HTTP 订阅服务本地端口（不占用公网）
    SINGLE_PORT_MODE=true
else
    # 多端口模式：保持原有逻辑
    TUIC_PORT=${AVAILABLE_PORTS[0]}
    HY2_PORT=${AVAILABLE_PORTS[1]}
    REALITY_PORT=${AVAILABLE_PORTS[0]}
    HTTP_PORT=${AVAILABLE_PORTS[1]}
    ARGO_PORT=8081
    SINGLE_PORT_MODE=false
fi

# ================== UUID ==================
UUID_FILE="${FILE_PATH}/uuid.txt"
[ -f "$UUID_FILE" ] && UUID=$(cat "$UUID_FILE") || { UUID=$(cat /proc/sys/kernel/random/uuid); echo "$UUID" > "$UUID_FILE"; }
echo "[UUID] $UUID"

# ================== 架构检测 & 下载 ==================
ARCH=$(uname -m)
[[ "$ARCH" == "aarch64" ]] && BASE_URL="https://arm64.ssss.nyc.mn" || BASE_URL="https://amd64.ssss.nyc.mn"
[[ "$ARCH" == "aarch64" ]] && ARGO_ARCH="arm64" || ARGO_ARCH="amd64"

SB_FILE="${FILE_PATH}/sb"
ARGO_FILE="${FILE_PATH}/cloudflared"

download_file() {
    local url=$1 output=$2
    [ -x "$output" ] && return 0
    echo "[下载] $output..."
    curl -L -sS --max-time 60 -o "$output" "$url" && chmod +x "$output" && echo "[下载] $output 完成" && return 0
    echo "[下载] $output 失败" && return 1
}

download_file "${BASE_URL}/sb" "$SB_FILE"
download_file "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARGO_ARCH}" "$ARGO_FILE"

# ================== Reality 密钥【强制生成】==================
echo "[密钥] 生成 Reality 密钥..."
KEY_FILE="${FILE_PATH}/key.txt"
if [ -f "$KEY_FILE" ]; then
    private_key=$(grep "PrivateKey:" "$KEY_FILE" | awk '{print $2}')
    public_key=$(grep "PublicKey:" "$KEY_FILE" | awk '{print $2}')
else
    output=$("$SB_FILE" generate reality-keypair)
    echo "$output" > "$KEY_FILE"
    private_key=$(echo "$output" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "$output" | awk '/PublicKey:/ {print $2}')
fi
echo "[密钥] 已就绪"

# ================== 证书生成 ==================
echo "[证书] 生成中..."
if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "${FILE_PATH}/private.key" -out "${FILE_PATH}/cert.pem" -days 3650 -subj "/CN=www.bing.com" >/dev/null 2>&1
else
    # 备用证书
    printf -- "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/+siNnfBYsdUYsoAoGCCqGSM49\nAwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASAnngZreoQDF16ARa/\nTsyLyFoPkhTxSbehH/OBEjHtSZGaDhMqQ==\n-----END EC PRIVATE KEY-----\n" > "${FILE_PATH}/private.key"
    printf -- "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgIUFWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwMTAxMDEwMTAwWhcNMzUwMTAxMDEw\nMTAwWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgJ54Ga3qEAxdegEWv07Mi8ha\nD5IU8Um3oR/zgRIx7UmRmg4TKkOjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\nBfGbgrkMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgrkMNzAPBgNVHRMB\nAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIARDAJvg0vd/ytrQVvEcSm6XTlB+\neQ6OFb9LbLYL9Zi+AiB+foMbi4y/0YUQlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n-----END CERTIFICATE-----\n" > "${FILE_PATH}/cert.pem"
fi
echo "[证书] 已就绪"

# ================== ISP ==================
ISP=$(curl -s --max-time 2 https://speed.cloudflare.com/meta 2>/dev/null | awk -F'"' '{print $26"-"$18}' | sed 's/-$//' || echo "Node")
[ -z "$ISP" ] && ISP="Node"

# ================== 生成 sing-box 配置【提前生成】==================
echo "[CONFIG] 生成配置..."
INBOUNDS=""

# TUIC (UDP)
if [ -n "$TUIC_PORT" ]; then
    INBOUNDS="{
        \"type\": \"tuic\",
        \"tag\": \"tuic-in\",
        \"listen\": \"::\",
        \"listen_port\": ${TUIC_PORT},
        \"users\": [{\"uuid\": \"${UUID}\", \"password\": \"admin\"}],
        \"congestion_control\": \"bbr\",
        \"tls\": {
            \"enabled\": true,
            \"alpn\": [\"h3\"],
            \"certificate_path\": \"${FILE_PATH}/cert.pem\",
            \"key_path\": \"${FILE_PATH}/private.key\"
        }
    }"
fi

# HY2 (UDP)
if [ -n "$HY2_PORT" ]; then
    [ -n "$INBOUNDS" ] && INBOUNDS="${INBOUNDS},"
    INBOUNDS="${INBOUNDS}{
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
        }
    }"
fi

# VLESS Reality (TCP)
if [ -n "$REALITY_PORT" ]; then
    [ -n "$INBOUNDS" ] && INBOUNDS="${INBOUNDS},"
    INBOUNDS="${INBOUNDS}{
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
        }
    }"
fi

# VLESS for Argo
INBOUNDS="${INBOUNDS},"
INBOUNDS="${INBOUNDS}{
    \"type\": \"vless\",
    \"tag\": \"vless-argo-in\",
    \"listen\": \"127.0.0.1\",
    \"listen_port\": ${ARGO_PORT},
    \"users\": [{\"uuid\": \"${UUID}\"}],
    \"transport\": {
        \"type\": \"ws\",
        \"path\": \"/${UUID}-vless\"
    }
}"

cat > "${FILE_PATH}/config.json" <<CFGEOF
{
    "log": {"level": "error"},
    "inbounds": [${INBOUNDS}],
    "outbounds": [{"type": "direct", "tag": "direct"}]
}
CFGEOF
echo "[CONFIG] 配置已生成"

# ================== 启动 sing-box【优先启动，占用公网端口】==================
echo "[SING-BOX] 启动中..."
"$SB_FILE" run -c "${FILE_PATH}/config.json" &
SB_PID=$!
sleep 2

if ! kill -0 $SB_PID 2>/dev/null; then
    echo "[SING-BOX] 启动失败"
    head -n 2 "${FILE_PATH}/private.key"
    "$SB_FILE" run -c "${FILE_PATH}/config.json"
    exit 1
fi
echo "[SING-BOX] 已启动 PID: $SB_PID"

# ================== HTTP 服务器脚本 + 启动【后启动，用本地端口】==================
cat > "${FILE_PATH}/server.js" <<JSEOF
const http = require('http');
const fs = require('fs');
const port = process.argv[2] || 8080;
const bind = process.argv[3] || '127.0.0.1'; // 仅监听本地回环，不占用公网
http.createServer((req, res) => {
    if (req.url.includes('/sub') || req.url.includes('/${UUID}')) {
        res.writeHead(200, {'Content-Type': 'text/plain; charset=utf-8'});
        try { res.end(fs.readFileSync('${FILE_PATH}/sub.txt', 'utf8')); } catch(e) { res.end('error'); }
    } else { res.writeHead(404); res.end('404'); }
}).listen(port, bind, () => console.log('HTTP on ' + bind + ':' + port));
JSEOF

echo "[HTTP] 启动订阅服务 (本地端口 $HTTP_PORT)..."
node "${FILE_PATH}/server.js" $HTTP_PORT 127.0.0.1 &
HTTP_PID=$!
sleep 1
echo "[HTTP] 订阅服务已启动 (仅本地可访问)"

# ================== 启动 Argo 隧道 ==================
ARGO_LOG="${FILE_PATH}/argo.log"
ARGO_DOMAIN=""

echo "[Argo] 启动隧道 (HTTP2模式)..."
"$ARGO_FILE" tunnel --edge-ip-version auto --protocol http2 --no-autoupdate --url http://127.0.0.1:${ARGO_PORT} > "$ARGO_LOG" 2>&1 &
ARGO_PID=$!

for i in {1..30}; do
    sleep 1
    ARGO_DOMAIN=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ARGO_LOG" 2>/dev/null | head -1 | sed 's|https://||')
    [ -n "$ARGO_DOMAIN" ] && break
done
[ -n "$ARGO_DOMAIN" ] && echo "[Argo] 域名: $ARGO_DOMAIN" || echo "[Argo] 获取域名失败"

# ================== 生成订阅 ==================
generate_sub() {
    local argo_domain="$1"
    > "${FILE_PATH}/list.txt"
    
    # TUIC (UDP)
    [ -n "$TUIC_PORT" ] && echo "tuic://${UUID}:admin@${PUBLIC_IP}:${TUIC_PORT}?sni=www.bing.com&alpn=h3&congestion_control=bbr&allowInsecure=1#TUIC-${ISP}" >> "${FILE_PATH}/list.txt"
    
    # HY2 (UDP)
    [ -n "$HY2_PORT" ] && echo "hysteria2://${UUID}@${PUBLIC_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1#Hysteria2-${ISP}" >> "${FILE_PATH}/list.txt"
    
    # Reality (TCP)
    [ -n "$REALITY_PORT" ] && echo "vless://${UUID}@${PUBLIC_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&fp=chrome&pbk=${public_key}&type=tcp#Reality-${ISP}" >> "${FILE_PATH}/list.txt"
    
    # Argo VLESS
    [ -n "$argo_domain" ] && echo "vless://${UUID}@${BEST_CF_DOMAIN}:443?encryption=none&security=tls&sni=${argo_domain}&type=ws&host=${argo_domain}&path=%2F${UUID}-vless#Argo-${ISP}" >> "${FILE_PATH}/list.txt"

    cat "${FILE_PATH}/list.txt" > "${FILE_PATH}/sub.txt"
    echo ""
    echo "==================================================="
    echo "【直接打印 - 节点信息完整列表】"
    echo "==================================================="
    if [ -s "${FILE_PATH}/list.txt" ]; then
        cat "${FILE_PATH}/list.txt"
    else
        echo "暂无可用节点信息"
    fi
    echo "==================================================="
    echo ""
}

# 生成订阅文件
generate_sub "$ARGO_DOMAIN"

# ================== 确定订阅链接 ==================
# 单端口模式下，订阅链接通过 Argo 隧道对外提供（避免公网端口冲突）
if [ "$SINGLE_PORT_MODE" = true ]; then
    if [ -n "$ARGO_DOMAIN" ]; then
        SUB_URL="http://${ARGO_DOMAIN}/sub"
    else
        SUB_URL="http://${PUBLIC_IP}:${HTTP_LOCAL_PORT}/sub (仅本地可访问)"
    fi
else
    SUB_URL="http://${PUBLIC_IP}:${HTTP_PORT}/sub"
fi

# ================== 输出结果 ==================
echo ""
echo "==================================================="
if [ "$SINGLE_PORT_MODE" = true ]; then
    echo "模式: 单端口多协议 (${SINGLE_PORT_UDP^^} + Reality + Argo)"
    echo ""
    echo "公网端口: ${PUBLIC_PORT} (UDP/TCP 共用)"
    echo "本地端口: HTTP订阅=${HTTP_LOCAL_PORT} | Argo本地=${ARGO_PORT}"
    echo "代理节点:"
    [ -n "$HY2_PORT" ] && echo "  - HY2 (UDP): ${PUBLIC_IP}:${HY2_PORT}"
    [ -n "$TUIC_PORT" ] && echo "  - TUIC (UDP): ${PUBLIC_IP}:${TUIC_PORT}"
    echo "  - Reality (TCP): ${PUBLIC_IP}:${REALITY_PORT}"
    [ -n "$ARGO_DOMAIN" ] && echo "  - Argo (WS): ${ARGO_DOMAIN}"
else
    echo "模式: 多端口 (TUIC + HY2 + Reality + Argo)"
    echo ""
    echo "代理节点:"
    echo "  - TUIC (UDP): ${PUBLIC_IP}:${TUIC_PORT}"
    echo "  - HY2 (UDP): ${PUBLIC_IP}:${HY2_PORT}"
    echo "  - Reality (TCP): ${PUBLIC_IP}:${REALITY_PORT}"
    [ -n "$ARGO_DOMAIN" ] && echo "  - Argo (WS): ${ARGO_DOMAIN}"
fi
echo ""
echo "订阅链接: $SUB_URL"
echo "==================================================="
echo ""

# ================== 保持运行 ==================
wait $SB_PID