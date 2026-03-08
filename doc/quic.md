

# ReceivedPacketTracker 类详细分析

## 核心功能概述

**ReceivedPacketTracker** 是 QUIC 协议实现中的一个关键组件，负责跟踪接收到的数据包并管理 ACK 生成和丢包检测所需的状态信息。该类位于 `AgentLinkCoro/src/base/net/quic/quic_packet_sorter.cc` 文件中。

## 设计思路

### 1. 区间合并优化

该类通过组合使用 **ReceivedPacketHistory** 类来高效管理已接收数据包的历史记录。核心设计思想是使用**区间合并算法**而非简单的位图或哈希表，这样可以：
- **节省内存**：特别是在高丢包率情况下
- **高效追踪**：快速确定数据包是否已接收、是否丢失
- **优化 ACK 帧大小**：使用合并的区间构造紧凑的 ACK 帧

### 2. ACK 策略设计

实现了复杂的 ACK 触发和延迟策略，包括：
- **数据包计数触发**：累积一定数量的需确认数据包后触发 ACK
- **延迟 ACK 机制**：设置 ACK 延迟定时器，平衡延迟和带宽
- **即时 ACK 场景**：对首次数据包、重传数据包和丢包检测场景立即发送 ACK

### 3. 丢包检测机制

通过观察数据包接收模式来检测潜在的丢包：
- 当接收到的数据包编号跳跃过大时（最高 ACK 范围起始值大于上一次最大确认值+1），且该数据包是单数据包时，认为存在丢包

## 核心组件关系

```
ReceivedPacketTracker
       |
       └──► ReceivedPacketHistory (管理接收历史记录)
       |
       └──► 与 SentPacketHandler 交互 (发送 ACK 和接收丢包通知)
```

## 主要方法分析

### 1. 构造函数

```cpp
ReceivedPacketTracker::ReceivedPacketTracker()
{
    m_packet_history = std::make_shared<ReceivedPacketHistory>();
}
```

初始化数据包历史记录器。

### 2. 数据包处理

```cpp
void ReceivedPacketTracker::receivedPacket(QuicPacketNumber pn, uint64_t recv_time, bool should_instigate_ack)
```

处理接收到的数据包，主要步骤：
- 加锁保护并发访问
- 忽略编号过小的数据包
- 检查数据包是否为之前标记为丢失的
- 更新最大观察到的数据包编号和时间
- 将数据包添加到历史记录中
- 根据需要触发 ACK 处理

### 3. ACK 决策

```cpp
void ReceivedPacketTracker::maybeQueueAck(QuicPacketNumber pn, uint64_t recv_time, bool was_missing)
```

决定是否应该将 ACK 帧加入发送队列，触发条件包括：
- 首次接收到数据包
- 接收到之前丢失的数据包
- 累积了足够数量（>= PacketsBeforeAck）的需确认数据包
- 检测到新的丢失数据包

### 4. ACK 帧生成

```cpp
QuicAckFrame::ptr ReceivedPacketTracker::getAckFrame(bool only_if_queued)
```
> 同一个数据包的ACK可能会被发送多次，直到该范围被忽略。
生成 ACK 帧并重置相关状态：
- 收集当前所有 ACK 范围
- 计算 ACK 延迟（从接收数据包到发送 ACK 的时间）
- 重置 ACK 相关计数器和标志

### 5. 丢包检测

```cpp
bool ReceivedPacketTracker::hasNewMissingPackets()
```

检查是否有新的丢失数据包需要报告，判断条件：
- 最高 ACK 范围的起始值大于上一次最大确认值+1
- 该范围长度为1（单数据包）

这表明收到了一个跳过中间编号的数据包，暗示中间数据包可能丢失。

### 6. 数据包状态检查

```cpp
bool ReceivedPacketTracker::isMissing(QuicPacketNumber pn)
```

检查数据包是否应该被视为丢失，判断条件：
- 数据包编号小于最大已确认编号
- 数据包未在 ACK 范围中

### 7. 历史记录优化

```cpp
void ReceivedPacketTracker::ignoreBelow(QuicPacketNumber pn)
```

忽略所有编号小于指定值的数据包，用于优化内存使用。

# SentPacketHandler 类详细分析

## 核心功能概述

**SentPacketHandler** 是 QUIC 协议实现中的另一个核心组件，负责管理已发送数据包的状态、处理收到的 ACK 帧、执行丢包检测和实现拥塞控制。该类位于 `AgentLinkCoro/src/base/net/quic/quic_packet_sorter.cc` 文件中，与 ReceivedPacketTracker 协同工作，共同保证 QUIC 协议的数据传输可靠性。

## 设计思路

### 1. 数据包生命周期管理

通过 **SentPacketHistory** 类实现数据包的完整生命周期管理：
- **发送跟踪**：记录所有已发送数据包的信息
- **状态维护**：维护数据包的各种状态（已发送、已确认、已丢失、已跳过）
- **内存优化**：定期清理已确认或已丢失的旧数据包，避免内存泄漏
- **高效查找**：提供快速查找和迭代已发送数据包的能力

### 2. 丢包检测与重传机制

实现了多层次的丢包检测策略：
- **基于时间的丢包检测**：当数据包超过特定时间阈值未收到 ACK 时视为丢失
- **基于编号的丢包检测**：当后续数据包已确认而中间数据包未确认时视为丢失
- **PTO（超时探测）机制**：当定时器超时时发送探测包确认连接状态
- **自适应超时策略**：基于 RTT 统计信息动态调整超时时间

### 3. ACK 处理与 RTT 估计

精心设计的 ACK 处理流程：
- **ACK 有效性验证**：防止接收错误的 ACK 信息
- **RTT 精确计算**：基于 ACK 延迟和数据包发送/接收时间计算真实 RTT
- **ACK 帧处理**：解析 ACK 帧，找出所有已确认的数据包
- **帧级确认通知**：通知每个帧它们已被确认，触发相应的回调处理

### 4. 拥塞控制集成

与 CUBIC 拥塞控制算法紧密集成：
- **飞行字节数管理**：精确跟踪网络中未确认的字节数
- **拥塞事件响应**：在检测到丢包时通知拥塞控制器
- **发送决策**：根据拥塞状态确定数据包的发送模式
- **探测包策略**：在网络状态不确定时发送探测包

## 核心组件关系

```
SentPacketHandler
       |
       ├──► SentPacketHistory (管理发送历史记录)
       |
       ├──► RTTStats (RTT统计信息管理)
       |
       ├──► CubicSender (拥塞控制算法实现)
       |
       └──► 与 ReceivedPacketTracker 交互 (接收 ACK 和发送丢包通知)
```

## 主要方法分析

### 1. 构造函数

```cpp
SentPacketHandler::SentPacketHandler(const RTTStats::ptr &rtt) : m_rtt_stats(rtt)
{
    // 初始化数据包历史记录
    m_data_packets.m_history = std::make_shared<SentPacketHistory>(m_rtt_stats);
    // 初始化CUBIC拥塞控制算法
    m_congestion = std::make_shared<CubicSender>(GetCurrentUS(), rtt, true, 1452);
}
```

初始化关键组件：数据包历史记录器和拥塞控制器。

### 2. 数据包发送处理

```cpp
void SentPacketHandler::sentPacket(QuicPacket::ptr packet, uint64_t now)
```

处理数据包发送，主要步骤：
- 更新发送字节数统计
- 调用内部实现处理数据包
- 设置数据包时间戳
- 将数据包记录到历史中
- 如果是需要 ACK 的数据包，设置丢包检测定时器

### 3. ACK 帧处理

```cpp
bool SentPacketHandler::receivedAck(QuicAckFrame::ptr frame, uint64_t recv_time)
```

处理收到的 ACK 帧，核心流程：
- 验证 ACK 的有效性（不能确认未发送的数据包）
- 更新最大确认的数据包编号
- 检测并移除已确认的数据包
- 更新 RTT 统计信息
- 重置 PTO 计数和探测包数量
- 清理旧的数据包历史
- 重新设置丢包检测定时器

### 4. 已确认数据包检测

```cpp
std::vector<QuicPacket::ptr> SentPacketHandler::detectAndRemoveAckedPackets(QuicAckFrame::ptr frame)
```

检测并处理已确认的数据包：
- 遍历 ACK 帧中的所有 ACK 范围
- 找出所有被确认的数据包
- 通知每个帧它们已被确认
- 从历史记录中移除已确认的数据包
- 返回已确认的数据包列表

### 5. 丢包检测

```cpp
bool SentPacketHandler::detectLostPackets(uint64_t now)
```

基于时间阈值检测丢失的数据包：
- 计算丢包检测延迟时间（基于 RTT 的倍数）
- 遍历所有数据包，检查是否超过丢包时间阈值
- 对于被检测为丢失的数据包，从飞行字节数中移除
- 通知拥塞控制器发生丢包
- 更新统计信息

### 6. 丢包检测超时处理

```cpp
bool SentPacketHandler::onLossDetectionTimeout()
```

处理丢包检测定时器超时事件：
- 执行丢包检测或准备发送探测包
- 增加 PTO 计数，调整下次超时时间
- 设置需要发送的探测包数量
- 重新设置丢包检测定时器

### 7. 探测包排队

```cpp
bool SentPacketHandler::queueProbePacket()
```

准备探测包进行重传：
- 获取第一个未完成的数据包
- 标记为丢失并排队其帧进行重传
- 更新字节流控信息

### 8. 发送模式决策

```cpp
PacketSendMode SentPacketHandler::sendMode()
```

确定当前的数据包发送模式：
- 检查跟踪的数据包数量，防止内存溢出
- 根据需要发送的探测包数量决定优先发送内容
- 根据拥塞控制状态决定是否允许发送新数据
- 返回适当的发送模式（无发送、只发送ACK、发送探测数据、允许任何发送）

### 9. 飞行字节数管理

```cpp
void SentPacketHandler::removeFromBytesInflight(QuicPacket::ptr packet)
```

从飞行中的字节数统计中移除数据包：
- 当数据包被确认或丢失时调用
- 更新飞行中的字节数（拥塞控制的关键参数）
- 进行防御性检查，避免统计错误

# QuicRcvStream 类详细分析 处理STREAM流帧

# 接收数据包
- QuicServer::handleData
- QuicSession::handleUnpackedPacket
    - QuicFrameCodec::parseNext 解析出所有的 QUIC帧
    - QuicPacketSorter::sortPacket 排序数据包
    - QuicFrameHandler::handleFrame 处理帧 
        - QuicFrameType::STREAM 处理流帧 QuicRcvStream::handleStreamFrame
        - QuicFrameType::ACK 处理确认帧 SentPacketHandler::receivedAck
        - QuicFrameType::CONNECTION_CLOSE 处理连接关闭帧 // TODO
        - QuicFrameType::MAX_DATA 处理最大数据帧 ConnectionFlowController::updateSendWin
        - QuicFrameType::MAX_STREAM_DATA 处理最大流数据帧 QuicSndStream::updateSendWin
        - QuicFrameType::RESET_STREAM 处理流重置帧 // todo
        - 阻塞相关 // todo
        
    - ReceivedPacketTracker::receivedPacket 通知接收包处理器收到了一个数据包，更新会话的接收状态