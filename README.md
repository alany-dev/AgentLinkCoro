# AI智能体通信


# 编译
ubuntu2204 apt 换源

```
cp /etc/apt/sources.list /etc/apt/sources.list.bak

vim /etc/apt/sources.list

deb http://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-proposed main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ jammy-proposed main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse

apt-get update
```


```bash
sudo apt install -y libhiredis-dev sqlite3 libtbb-dev

pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/
pip install --upgrade pip
pip install "urllib3<2.0" "chardet<5.0"
pip install conan

source ~/.profile
conan profile detect # 创建默认配置文件
vim ~/.conan2/profiles/default
# 自己调整 并行构建线程数
# [conf]
# tools.build:jobs=2
source ~/.profile

mkdir build && cd build
conan install ..
conan install .. --build=missing # 有些依赖需要本地构建
```

# 技术实现进度
- ✅ 协程网络库
- ✅ Rock RPC （自定义二进制协议）
- ⬜ dpdk 实现用户态 TCP/IP 协议栈
- ⬜ ebpf 监控
- ⬜ MCP Server
- ⬜ Agent 智能体协调 
- ❎ quic 暂时搁置，在 dev_quic 分支

# 参考项目
- [sylar](https://github.com/sylar-yin/sylar)
- [quic-fiber](https://github.com/hankai17/quic-fiber)