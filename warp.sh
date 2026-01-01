#!/bin/bash
set -e

echo "脚本开始执行: $(date)"

# 定义文件下载地址和名称
MASQUE_PLUS_URL="https://cdn.jsdelivr.net/gh/masx200/singbox-nodejs-warp@main/masque-plus.zip"
MASQUE_PLUS_ZIP="masque-plus.zip"
MASQUE_PLUS_EXE="masque-plus"

USQUE_URL="https://cdn.jsdelivr.net/gh/masx200/singbox-nodejs-warp@main/usque.zip"
USQUE_ZIP="usque.zip"
USQUE_EXE="usque"

# 检查并安装依赖
check_dependencies() {
    local missing_deps=0
    echo "检查依赖工具..."
    if ! command -v wget &> /dev/null; then
        echo "错误: 未安装 wget。请安装它。"
        echo "  - Alpine: apk add wget"
        missing_deps=1
    fi
    if ! command -v unzip &> /dev/null; then
        echo "错误: 未安装 unzip。请安装它。"
        echo "  - Alpine: apk add unzip"
        missing_deps=1
    fi
    if [ $missing_deps -ne 0 ]; then
        exit 1
    fi
    echo "依赖检查通过。"
}

# 下载并解压文件的通用函数
download_and_extract() {
    local url=$1
    local zip_file=$2
    local exe_file=$3

    if [ ! -f "./$exe_file" ]; then
        echo "正在下载 $exe_file..."
        wget -v -O "$zip_file" "$url"
        
        if [ $? -ne 0 ]; then
            echo "错误: 下载 $zip_file 失败。请检查网络连接或 URL。"
            rm -f "$zip_file"
            exit 1
        fi

        echo "正在解压 $zip_file..."
        unzip -o "$zip_file"
        
        if [ $? -ne 0 ]; then
            echo "错误: 解压 $zip_file 失败。文件可能已损坏。"
            rm -f "$zip_file"
            exit 1
        fi

        rm -f "$zip_file"
        chmod +x "./$exe_file"
        echo "$exe_file 下载并设置完成"
    else
        echo "$exe_file 已存在，跳过下载"
    fi
}

# --- 主程序开始 ---

# 1. 检查依赖
check_dependencies

# 2. 下载和设置 masque-plus
download_and_extract "$MASQUE_PLUS_URL" "$MASQUE_PLUS_ZIP" "$MASQUE_PLUS_EXE"

# 3. 下载和设置 usque
download_and_extract "$USQUE_URL" "$USQUE_ZIP" "$USQUE_EXE"

# 4. 运行主程序
echo "所有准备工作完成，开始运行主程序..."
while true; do
    echo "正在启动 $MASQUE_PLUS_EXE ..."
    ./$MASQUE_PLUS_EXE "-bind" "0.0.0.0:1080" "-username" "g7envpwz14b0u55" "--password" "juvytdsdzc225pq" "-endpoint" "www.bing.com:443" "-sni"  "www.bing.com" "-dns" "1.1.1.1,8.8.8.8,94.140.14.140"
    
    echo "$MASQUE_PLUS_EXE 进程意外退出，10秒后将自动重启..."
    sleep 10
done