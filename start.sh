#!/bin/ash
# =========================
# 老王sing-box四合一脚本（Alpine amd64 非root版）
# 增加节点信息写入日志功能
# =========================

export LANG=en_US.UTF-8
# 定义颜色（ash兼容）
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
skyblue="\e[1;36m"

red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }

# 用户目录配置（非root）
USER_HOME=$(eval echo ~${SUDO_USER:-$USER})
work_dir="${USER_HOME}/.sing-box"
config_dir="${work_dir}/config.json"
client_dir="${work_dir}/url.txt"
sub_file="${work_dir}/sub_base64.txt"
log_dir="${work_dir}/logs"
node_log="${log_dir}/node_info.log"  # [新增日志] 节点信息日志文件
export vless_port=${PORT:-$(shuf -i 1025-65000 -n 1)}
export CFIP=${CFIP:-'cf.877774.xyz'} 
export CFPORT=${CFPORT:-'443'} 

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 获取IP
get_realip() {
    ip=$(curl -4 -sm 2 ip.sb)
    ipv6() { curl -6 -sm 2 ip.sb; }
    if [ -z "$ip" ]; then
        echo "[$(ipv6)]"
    elif curl -4 -sm 2 http://ipinfo.io/org | grep -qE 'Cloudflare|UnReal|AEZA|Andrei'; then
        echo "[$(ipv6)]"
    else
        resp=$(curl -sm 8 "https://status.eooce.com/api/$ip" | jq -r '.status')
        if [ "$resp" = "Available" ]; then
            echo "$ip"
        else
            v6=$(ipv6)
            [ -n "$v6" ] && echo "[$v6]" || echo "$ip"
        fi
    fi
}

# 安装sing-box（Alpine amd64）
install_singbox() {
    purple "正在安装sing-box到用户目录，请稍后..."
    mkdir -p "${work_dir}" "${log_dir}" && chmod 777 "${work_dir}" "${log_dir}"
    > "${node_log}"  # [新增日志] 清空原有节点日志（避免重复）

    # 强制amd64架构（Alpine x86_64）
    ARCH="amd64"
    # 下载二进制文件
    curl -sLo "${work_dir}/qrencode" "https://$ARCH.ssss.nyc.mn/qrencode"
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
    curl -sLo "${work_dir}/argo" "https://$ARCH.ssss.nyc.mn/bot"
    chmod +x "${work_dir}/sing-box" "${work_dir}/argo" "${work_dir}/qrencode"

    # 生成端口/密码/密钥
    tuic_port=$(($vless_port + 2))
    hy2_port=$(($vless_port + 3)) 
    uuid=$(cat /proc/sys/kernel/random/uuid)
    password=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 24)
    output=$("${work_dir}/sing-box" generate reality-keypair)
    private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')

    # 生成自签名证书（Alpine openssl兼容）
    openssl ecparam -genkey -name prime256v1 -out "${work_dir}/private.key"
    openssl req -new -x509 -days 3650 -key "${work_dir}/private.key" -out "${work_dir}/cert.pem" -subj "/CN=bing.com"
    
    # DNS策略检测
    dns_strategy=$(ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 && echo "prefer_ipv4" || (ping -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1 && echo "prefer_ipv6" || echo "prefer_ipv4"))

    # 生成sing-box配置文件
cat > "${config_dir}" << EOF
{
  "log": {
    "disabled": false,
    "level": "error",
    "output": "${log_dir}/sb.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "local",
        "strategy": "$dns_strategy"
      }
    ]
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": $vless_port,
      "users": [
        {
          "uuid": "$uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.iij.ad.jp",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.iij.ad.jp",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": [""]
        }
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": 8001,
      "users": [
        {
          "uuid": "$uuid"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess-argo",
        "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2",
      "listen": "::",
      "listen_port": $hy2_port,
      "users": [
        {
          "password": "$uuid"
        }
      ],
      "ignore_client_bandwidth": false,
      "masquerade": "https://bing.com",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "min_version": "1.3",
        "max_version": "1.3",
        "certificate_path": "${work_dir}/cert.pem",
        "key_path": "${work_dir}/private.key"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": $tuic_port,
      "users": [
        {
          "uuid": "$uuid",
          "password": "$password"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "${work_dir}/cert.pem",
        "key_path": "${work_dir}/private.key"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "engage.cloudflareclient.com",
      "server_port": 2408,
      "local_address": [
        "172.16.0.2/32",
        "2606:4700:110:851f:4da3:4e2c:cdbf:2ecf/128"
      ],
      "private_key": "eAx8o6MJrH4KE7ivPFFCa4qvYw5nJsYHCBQXPApQX1A=",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": [82, 90, 51],
      "mtu": 1420
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/openai.srs",
        "download_detour": "direct"
      },
      {
        "tag": "netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/netflix.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      {
        "all": true,
        "outbound": "wireguard-out"
      }
    ],
    "final": "wireguard-out"
  }
}
EOF
}

# 生成节点信息（增加日志写入）
get_info() {  
  yellow "\nip检测中,请稍等...\n"
  server_ip=$(get_realip)
  isp=$(curl -s --max-time 2 https://ipapi.co/json | tr -d '\n[:space:]' | sed 's/.*"country_code":"\([^"]*\)".*"org":"\([^"]*\)".*/\1-\2/' | sed 's/ /_/g' 2>/dev/null || echo "$hostname")

  # 获取Argo域名
  if [ -f "${log_dir}/argo.log" ]; then
      for i in 1 2 3 4 5; do
          purple "第 $i 次尝试获取ArgoDomain中..."
          argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${log_dir}/argo.log")
          [ -n "$argodomain" ] && break
          sleep 2
      done
  else
      restart_argo
      sleep 6
      argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${log_dir}/argo.log")
  fi

  # [新增日志] 写入基础信息到日志
  echo "==================================== 节点信息（生成时间：$(date)）====================================" >> "${node_log}"
  echo "服务器IP: ${server_ip}" >> "${node_log}"
  echo "ISP信息: ${isp}" >> "${node_log}"
  echo "Argo域名: ${argodomain}" >> "${node_log}"
  echo "VLESS端口: ${vless_port} | HY2端口: ${hy2_port} | TUIC端口: ${tuic_port}" >> "${node_log}"
  echo "UUID: ${uuid} | 随机密码: ${password}" >> "${node_log}"
  echo "Reality公钥: ${public_key}" >> "${node_log}"
  echo "-------------------------------------------------------------------------------------------" >> "${node_log}"

  green "\nArgoDomain：${purple}$argodomain${re}\n"

  # 生成VMESS配置
  VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"firefox\", \"allowlnsecure\": \"flase\"}"

  # 写入节点文件（本地）
  cat > ${client_dir} <<EOF
vless://${uuid}@${server_ip}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${public_key}&type=tcp&headerType=none#${isp}

vmess://$(echo "$VMESS" | base64 -w0)

hysteria2://${uuid}@${server_ip}:${hy2_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}

tuic://${uuid}:${password}@${server_ip}:${tuic_port}?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#${isp}
EOF

  # 生成本地订阅文件（base64编码）
  base64 -w0 ${client_dir} > ${sub_file}
  chmod 644 ${sub_file}

  # [新增日志] 写入节点链接和订阅路径到日志
  echo -e "\n=== 节点链接 ===" >> "${node_log}"
  cat ${client_dir} >> "${node_log}"
  echo -e "\n=== 本地文件路径 ===" >> "${node_log}"
  echo "节点文件: ${client_dir}" >> "${node_log}"
  echo "订阅文件(base64): ${sub_file}" >> "${node_log}"
  echo "节点日志文件: ${node_log}" >> "${node_log}"
  echo "==========================================================================================" >> "${node_log}"
  echo -e "\n" >> "${node_log}"

  # ========== 终端输出（原有逻辑不变） ==========
  green "==================================== 节点信息（可直接复制）===================================="
  echo ""
  while IFS= read -r line; do echo -e "${purple}$line"; done < ${client_dir}
  echo ""
  green "=========================================================================================="
  
  # 输出本地订阅文件路径 + 日志文件路径
  yellow "\n📌 本地订阅文件（base64编码）：${sub_file}"
  green "📌 节点日志文件（永久保存）：${node_log}\n"  # [新增日志] 提示日志路径
  green "可通过命令查看节点日志：cat ${node_log}\n"

  # 生成二维码（仅VLESS，终端显示）
  purple "VLESS节点二维码："
  "${work_dir}/qrencode" "$(head -1 ${client_dir})"
  
  yellow "\n温馨提醒：需打开V2rayN等软件的「跳过证书验证」\n"
}

# 启动进程（nohup后台运行，无python）
start_processes() {
    stop_processes
    # 启动sing-box
    nohup "${work_dir}/sing-box" run -c "${config_dir}" > "${log_dir}/sb.log" 2>&1 &
    echo $! > "${work_dir}/sb.pid"
    green "sing-box 已启动，PID: $(cat ${work_dir}/sb.pid)\n"
    # 启动argo隧道
    nohup "${work_dir}/argo" tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2 > "${log_dir}/argo.log" 2>&1 &
    echo $! > "${work_dir}/argo.pid"
    green "Argo隧道 已启动，PID: $(cat ${work_dir}/argo.pid)\n"
    sleep 5
}

# 停止进程
stop_processes() {
    [ -f "${work_dir}/sb.pid" ] && kill $(cat "${work_dir}/sb.pid") 2>/dev/null || true
    [ -f "${work_dir}/argo.pid" ] && kill $(cat "${work_dir}/argo.pid") 2>/dev/null || true
    rm -f "${work_dir}/sb.pid" "${work_dir}/argo.pid"
    pkill -f "${work_dir}/sing-box" 2>/dev/null || true
    pkill -f "${work_dir}/argo" 2>/dev/null || true
}

# 检查进程状态
check_status() {
    green "=== 进程状态 ===\n"
    if ! command_exists "ps"; then
        red "未安装procps-ng，无法查看进程状态\n"
        return 1
    fi
    if ps -p $(cat "${work_dir}/sb.pid" 2>/dev/null) >/dev/null 2>&1; then
        green "sing-box: 运行中 (PID: $(cat ${work_dir}/sb.pid))"
    else
        red "sing-box: 未运行"
    fi
    if ps -p $(cat "${work_dir}/argo.pid" 2>/dev/null) >/dev/null 2>&1; then
        green "Argo隧道: 运行中 (PID: $(cat ${work_dir}/argo.pid))"
    else
        red "Argo隧道: 未运行"
    fi
    # [新增日志] 状态中提示日志路径
    green "\n📌 节点日志文件：${node_log}\n"
}

# 检查依赖（移除python3）
check_dependencies() {
    green "=== 检查依赖 ===\n"
    local dependencies=("curl" "openssl" "jq" "ping" "procps-ng" "coreutils")
    local missing=()
    for dep in "${dependencies[@]}"; do
        if ! command_exists "$dep"; then
            missing+=("$dep")
        else
            green "$dep: 已安装"
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        red "缺少依赖: ${missing[*]}"
        red "请用root执行：apk add ${missing[*]}\n"
        exit 1
    fi
    echo ""
}

# 重启argo
restart_argo() {
    stop_processes
    nohup "${work_dir}/argo" tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2 > "${log_dir}/argo.log" 2>&1 &
    echo $! > "${work_dir}/argo.pid"
}

# 卸载脚本
uninstall() {
    stop_processes
    rm -rf "${work_dir}"
    green "已卸载：所有文件已删除\n"
    exit 0
}

# 主流程
main() {
    check_dependencies
    stop_processes
    install_singbox
    start_processes
    get_info
    check_status
    green "=== 使用说明 ===\n"
    green "1. 停止服务: ash $0 stop"
    green "2. 重启服务: ash $0 restart"
    green "3. 查看状态: ash $0 status"
    green "4. 卸载脚本: ash $0 uninstall"
    green "5. 查看节点: cat ${client_dir}"
    green "6. 查看订阅: cat ${sub_file}"
    green "7. 查看节点日志: cat ${node_log}\n"  # [新增日志] 增加查看日志的命令
}

# 命令行参数处理
case "$1" in
    "start") start_processes; check_status ;;
    "stop") stop_processes; green "已停止所有进程\n" ;;
    "restart") stop_processes; start_processes; check_status ;;
    "status") check_status ;;
    "uninstall") uninstall ;;
    *) main ;;
esac