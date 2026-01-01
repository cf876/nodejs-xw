#!/bin/bash
set -e

echo "warp start"

# 定义文件下载地址
MASQUE_PLUS_URL="https://cdn.jsdelivr.net/gh/masx200/singbox-nodejs-warp@main/masque-plus.zip"
USQUE_URL="https://cdn.jsdelivr.net/gh/masx200/singbox-nodejs-warp@main/usque.zip"

# 检查并下载 masque-plus
if [ ! -f "./masque-plus" ]; then
    echo "下载 masque-plus..."
    rm masque-plus.zip || true
    wget -q -O masque-plus.zip "$MASQUE_PLUS_URL"
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
    wget  -q -O usque.zip "$USQUE_URL"
    unzip -o usque.zip
    rm usque.zip
    chmod +x ./usque
    echo "usque 下载并设置完成"
else
    echo "usque 已存在，跳过下载"
fi
while true; do
    
    
    
    
    ./masque-plus "-bind" "0.0.0.0:1080" "-username" "g7envpwz14b0u55" "--password" "juvytdsdzc225pq" "-endpoint" "162.159.198.2:443" "-sni"  "gitlab.io" "-dns" "1.1.1.1,8.8.8.8,94.140.14.140"
    
    
    
    sleep 10
done
