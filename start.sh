##!/bin/bash
set -e

echo "start start"
# ================== 端口设置 ==================
export TUIC_PORT=${PORT:-"7860"}
export HY2_PORT=${HY2_PORT:-""}
export REALITY_PORT=${PORT:-"7860"}

# ================== 强制切换到脚本所在目录 ==================
cd "$(dirname "$0")"

# ================== 环境变量 & 绝对路径 ==================
export FILE_PATH="${PWD}/.npm"
export DATA_PATH="${PWD}/singbox_data"
mkdir -p "$FILE_PATH" "$DATA_PATH"

# ================== UUID 固定保存（核心逻辑）==================
UUID_FILE="${FILE_PATH}/uuid.txt"
if [ -f "$UUID_FILE" ]; then
  UUID=$(cat "$UUID_FILE")
  echo -e "\e[1;33m[UUID] 复用固定 UUID: $UUID\e[0m"
else
  UUID=$(cat /proc/sys/kernel/random/uuid)
  echo "$UUID" > "$UUID_FILE"
  chmod 600 "$UUID_FILE"
  echo -e "\e[1;32m[UUID] 首次生成并永久保存: $UUID\e[0m"
fi

# ================== 创建目录 ==================
[ ! -d "${FILE_PATH}" ] && mkdir -p "${FILE_PATH}"

# ================== 架构检测 & 下载 sing-box ==================
ARCH=$(uname -m)
BASE_URL=""
if [[ "$ARCH" == "arm"* ]] || [[ "$ARCH" == "aarch64" ]]; then
  BASE_URL="https://arm64.ssss.nyc.mn"
elif [[ "$ARCH" == "amd64"* ]] || [[ "$ARCH" == "x86_64" ]]; then
  BASE_URL="https://amd64.ssss.nyc.mn"
elif [[ "$ARCH" == "s390x" ]]; then
  BASE_URL="https://s390x.ssss.nyc.mn"
else
  echo "不支持的架构: $ARCH"
  exit 1
fi

FILE_INFOS=("sb sing-box")
declare -A FILE_MAP

download_file() {
  local URL=$1
  local FILENAME=$2
  if command -v curl >/dev/null 2>&1; then
    curl -L -sS -o "$FILENAME" "$URL" && echo -e "\e[1;32m下载 $FILENAME (curl)\e[0m"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$FILENAME" "$URL" && echo -e "\e[1;32m下载 $FILENAME (wget)\e[0m"
  else
    echo -e "\e[1;31m未找到 curl 或 wget\e[0m"
    exit 1
  fi
}

# ================== 清理旧的 sing-box 可执行文件 ==================
echo -e "\e[1;33m[清理] 正在清理旧的 sing-box 可执行文件...\e[0m"
# 删除6位随机命名的可执行文件（旧的sing-box文件），但保留配置文件
find "${FILE_PATH}" -type f -name '??????' -executable -exec rm -f {} \; 2>/dev/null || true
# 额外清理：删除所有6位随机字符的文件（除了我们已知的配置文件）
cd "${FILE_PATH}"
for file in ??????; do
  if [[ -f "$file" && "$file" != "uuid.txt" && "$file" != "key.txt" && "$file" != "cert.pem" && "$file" != "private.key" && "$file" != "config.json" && "$file" != "list.txt" && "$file" != "sub.txt" ]]; then
    rm -f "$file" 2>/dev/null || true
  fi
done
# 切换回脚本目录
cd - > /dev/null
echo -e "\e[1;32m[清理] 旧文件清理完成\e[0m"

for entry in "${FILE_INFOS[@]}"; do
  URL=$(echo "$entry" | cut -d ' ' -f1)
  NAME=$(echo "$entry" | cut -d ' ' -f2)
  NEW_NAME="${FILE_PATH}/$(head /dev/urandom | tr -dc a-z0-9 | head -c6)"
  download_file "${BASE_URL}/${URL}" "$NEW_NAME"
  chmod +x "$NEW_NAME"
  FILE_MAP[$NAME]="$NEW_NAME"
done

echo "warp start"

# 定义文件下载地址
MASQUE_PLUS_URL="https://cdn.jsdelivr.net/gh/masx200/singbox-nodejs-warp-xray-tunnel@main/masque-plus.zip"
USQUE_URL="https://cdn.jsdelivr.net/gh/masx200/singbox-nodejs-warp-xray-tunnel@main/usque.zip"

# 检查并下载 masque-plus
if [ ! -f "./masque-plus" ]; then
    echo "下载 masque-plus..."
    rm masque-plus.zip || true
    wget -v -O masque-plus.zip "$MASQUE_PLUS_URL"
    unzip -o masque-plus.zip
    rm masque-plus.zip
    chmod +x ./masque-plus
    echo "masque-plus 下载并设置完成"
else
    echo "masque-plus 已存在，跳过下载"
fi

# 检查并下载 usque
if [ ! -f "./usque" ]; then
    echo "下载 usque..."
    rm usque.zip || true
    wget  -v -O usque.zip "$USQUE_URL"
    unzip -o usque.zip
    rm usque.zip
    chmod +x ./usque
    echo "usque 下载并设置完成"
else
    echo "usque 已存在，跳过下载"
fi



while true; do
    
    
       ./masque-plus "-bind" "0.0.0.0:1080" "-username" "hp40emnw108got6a67p2isj1x65qwjtz60fh5dtl7nhjhor3va" "--password" "i7esr1nwxcil034gslw4sdzjyfejfvf5xiaagx4x286nw6l3ff"  "-sni"  "gitlab.io" "-dns" "1.1.1.1,8.8.8.8,94.140.14.140" "-scan" "-4"                "-range4"                   "162.159.199.2/32"
    
    
    
    sleep 10
    
    ./masque-plus "-bind" "0.0.0.0:1080" "-username" "hp40emnw108got6a67p2isj1x65qwjtz60fh5dtl7nhjhor3va" "--password" "i7esr1nwxcil034gslw4sdzjyfejfvf5xiaagx4x286nw6l3ff"  "-sni"  "gitlab.io" "-dns" "1.1.1.1,8.8.8.8,94.140.14.140" "-scan" "-4"                "-range4"                   "162.159.198.2/32"
    
    
    
    sleep 10
done

# ================== 固定 Reality 密钥 ==================
KEY_FILE="${FILE_PATH}/key.txt"
if [ -f "$KEY_FILE" ]; then
  echo -e "\e[1;33m[密钥] 检测到已有密钥，复用...\e[0m"
  private_key=$(grep "PrivateKey:" "$KEY_FILE" | awk '{print $2}')
  public_key=$(grep "PublicKey:" "$KEY_FILE" | awk '{print $2}')
else
  echo -e "\e[1;33m[密钥] 首次生成 Reality 密钥对...\e[0m"
  output=$("${FILE_MAP[sing-box]}" generate reality-keypair)
  echo "$output" > "$KEY_FILE"
  private_key=$(echo "$output" | awk '/PrivateKey:/ {print $2}')
  public_key=$(echo "$output" | awk '/PublicKey:/ {print $2}')
  chmod 600 "$KEY_FILE"
  echo -e "\e[1;32m[密钥] 密钥已保存，重启后保持不变\e[0m"
fi

# ================== 生成证书（自签或固定）==================
if [ -f "${FILE_PATH}/private.key" ] && [ -f "${FILE_PATH}/cert.pem" ]; then
  echo -e "\e[1;33m[证书] 检测到已有证书，复用...\e[0m"
else
  echo -e "\e[1;33m[证书] 正在生成证书...\e[0m"
  if ! command -v openssl >/dev/null 2>&1; then
    cat > "${FILE_PATH}/private.key" <<'EOF'
-----BEGIN EC PARAMETERS-----
BgqghkjOPQQBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/+siNnfBYsdUYsAoGCCqGSM49
AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASAnngZreoQDF16ARa
/TsyLyFoPkhTxSbehH/OBEjHtSZGaDhMqQ==
-----END EC PRIVATE KEY-----
EOF
    cat > "${FILE_PATH}/cert.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIUFWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwMTAxMDEwMTAwWhcNMzUwMTAxMDEw
MTAwWjATMREwDwYDVQQDDAhiaW5nLmNvbTBNBgqgGzM9AgEGCCqGSM49AwEHA0IA
BNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdeWv07Mi8h
d5IR8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBQTV1cFID7UISE7PLTBR
BfGbgrkMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgrkMNzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIARDAJvg0vd/ytrQVvEcSm6XTlB+
eQ6OFb9LbLYL9Zi+AiffoMbi4y/0YUQlTtz7as9S8/lciBF5VCUoVIKS+vX2g==
-----END CERTIFICATE-----
EOF
  else
    openssl ecparam -genkey -name prime256v1 -out "${FILE_PATH}/private.key" 2>/dev/null
    openssl req -new -x509 -days 3650 -key "${FILE_PATH}/private.key" -out "${FILE_PATH}/cert.pem" -subj "/CN=www.bing.com" 2>/dev/null
  fi
  chmod 600 "${FILE_PATH}/private.key"
  echo -e "\e[1;32m[证书] 证书已生成\e[0m"

  # ================== 计算 pinSHA256 ==================
  # ================== 计算 pinSHA256 ==================
  # Hysteria2 需要整个证书的 SHA256，而不仅仅是公钥
  PINSHA256=$(openssl x509 -in "${FILE_PATH}/cert.pem" -outform DER 2>/dev/null | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $2}')
  echo -e "\e[1;36m[证书] pinSHA256: ${PINSHA256}\e[0m"
fi

# ================== 生成 config.json ==================
cat > "${FILE_PATH}/config.json" <<EOF
{


  "log": { "disabled": false ,"level": "info"},
  "inbounds": [$( \
    [ "$TUIC_PORT" != "" ] && [ "$TUIC_PORT" != "0" ] && echo "{
      \"type\": \"tuic\",
      \"listen\": \"::\",
      \"listen_port\": $TUIC_PORT,
      \"users\": [{\"uuid\": \"$UUID\", \"password\": \"admin\"}],
      \"congestion_control\": \"bbr\",
      \"tls\": {\"enabled\": true, \"alpn\": [\"h3\"], \"certificate_path\": \"${FILE_PATH}/cert.pem\", \"key_path\": \"${FILE_PATH}/private.key\"}
    },"; \
    [ "$HY2_PORT" != "" ] && [ "$HY2_PORT" != "0" ] && echo "{
      \"type\": \"hysteria2\",
      \"listen\": \"::\",
      \"listen_port\": $HY2_PORT,
      \"users\": [{\"password\": \"$UUID\"}],
      \"masquerade\": \"https://www.bing.com\",
      \"tls\": {\"enabled\": true, \"alpn\": [\"h3\"], \"certificate_path\": \"${FILE_PATH}/cert.pem\", \"key_path\": \"${FILE_PATH}/private.key\"}
    },"; \
    [ "$REALITY_PORT" != "" ] && [ "$REALITY_PORT" != "0" ] && echo "{
      \"type\": \"vless\",
      \"listen\": \"::\",
      \"listen_port\": $REALITY_PORT,
      \"users\": [{\"uuid\": \"$UUID\", \"flow\": \"xtls-rprx-vision\"}],
      \"tls\": {
        \"enabled\": true,
        \"server_name\": \"www.nazhumi.com\",
        \"reality\": {
          \"enabled\": true,
          \"handshake\": {\"server\": \"www.nazhumi.com\", \"server_port\": 443},
          \"private_key\": \"$private_key\",
          \"short_id\": [\"\"]
        }
      }
    }"; \
  )],
  "outbounds": [
  
  {"type": "direct"},
  
  
  
   {
      "type": "socks",
      "tag": "warp-PROXY",
      "server": "127.0.0.1",
      "server_port": 1080,
      "version": "5",
      "username": "hp40emnw108got6a67p2isj1x65qwjtz60fh5dtl7nhjhor3va",
      "password": "i7esr1nwxcil034gslw4sdzjyfejfvf5xiaagx4x286nw6l3ff"
    }


  ],
   "route": {
    "rules": [
      {
        "domain": [".*"],
        "outbound": "warp-PROXY"
      },
      {
        "protocol": "dns",
        "outbound": "warp-PROXY"
      }
    ],
    "final": "warp-PROXY"
  }
}
EOF

# ================== 启动 sing-box ==================
"${FILE_MAP[sing-box]}" run -c "${FILE_PATH}/config.json" &
SINGBOX_PID=$!
echo "[SING-BOX] 启动完成 PID=$SINGBOX_PID"

# ================== 获取 IP & ISP ==================
IP=$(curl -s --max-time 20   https://api-ipv4.ip.sb/ip -H "user-agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36" || curl -s --max-time 1 api.ipify.org || echo "IP_ERROR")
ISP=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F'"' '{print $26"-"$18}' || echo "0.0")

# ================== 生成订阅 ==================
# 重新计算 pinSHA256（如果证书已存在，从现有证书计算；如果刚生成，重新计算）
 # ================== 计算 pinSHA256 ==================
  # Hysteria2 需要整个证书的 SHA256，而不仅仅是公钥
  PINSHA256=$(openssl x509 -in "${FILE_PATH}/cert.pem" -outform DER 2>/dev/null | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $2}')

> "${FILE_PATH}/list.txt"
[ "$TUIC_PORT" != "" ] && [ "$TUIC_PORT" != "0" ] && echo "tuic://${UUID}:admin@${IP}:${TUIC_PORT}?sni=www.bing.com&alpn=h3&congestion_control=bbr&allowInsecure=1#TUIC-${ISP}" >> "${FILE_PATH}/list.txt"
[ "$HY2_PORT" != "" ] && [ "$HY2_PORT" != "0" ] && echo "hysteria2://${UUID}@${IP}:${HY2_PORT}/?sni=www.bing.com&pinSHA256=${PINSHA256}&insecure=1#Hysteria2-${ISP}" >> "${FILE_PATH}/list.txt"
[ "$REALITY_PORT" != "" ] && [ "$REALITY_PORT" != "0" ] && echo "vless://${UUID}@${IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&fp=firefox&pbk=${public_key}&type=tcp#Reality-${ISP}" >> "${FILE_PATH}/list.txt"

base64 "${FILE_PATH}/list.txt" | tr -d '\n' > "${FILE_PATH}/sub.txt"
cat "${FILE_PATH}/list.txt"
echo -e "\n\e[1;32m${FILE_PATH}/sub.txt 已保存\e[0m"

# ================== 启动定时重启（前台阻塞） ==================
schedule_restart() {
  echo "[定时重启:Sing-box] 已启动（北京时间 00:03）"
  LAST_RESTART_DAY=-1

  while true; do
    now_ts=$(date +%s)
    beijing_ts=$((now_ts + 28800))
    H=$(( (beijing_ts / 3600) % 24 ))
    M=$(( (beijing_ts / 60) % 60 ))
    D=$(( beijing_ts / 86400 ))

    # ---- 时间匹配 → 重启 sing-box ----
    if [ "$H" -eq 00 ] && [ "$M" -eq 03 ] && [ "$D" -ne "$LAST_RESTART_DAY" ]; then
      echo "[定时重启:Sing-box] 到达 00:03 → 重启 sing-box"
      LAST_RESTART_DAY=$D

      kill "$SINGBOX_PID" 2>/dev/null || true
      sleep 3

      "${FILE_MAP[sing-box]}" run -c "${FILE_PATH}/config.json" &
      SINGBOX_PID=$!

      echo "[Sing-box重启完成] 新 PID: $SINGBOX_PID"
    fi

    sleep 10
  done
}

# ★★★ 关键：保持脚本前台运行，不能退出
schedule_restart
