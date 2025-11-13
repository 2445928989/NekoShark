# Packet Capture & Analysis Tool

基于 Python 开发的图形化网络流量分析软件，可在单机环境下运行并提供近似 Wireshark 的报文解析、过滤、统计及资源监测能力。

## 功能概述

- **实时抓包**：使用 Scapy 异步嗅探器捕获网络流量，支持输入 BPF 过滤表达式来限定抓包范围。
- **分层解析**：在 GUI 中逐字段展示数据链路层、网络层（IPv4/IPv6/ARP）与传输层（TCP/UDP/ICMP）信息，同时识别 DNS 报文。
- **过滤器设计**：顶部提供 BPF 过滤器输入框，可输入如 `tcp port 80`、`host 192.168.1.1` 等表达式来控制捕获内容。
- **统计与可视化**：
  - 表格统计 IPv4、IPv6、TCP、UDP、ARP、DNS 的报文数量。
  - 折线图展示最近 24 小时 IPv6 报文占比随时间的变化，可满足“至少 1 天”的时间跨度要求。
  - 柱状图实时显示 TCP、UDP、ARP 报文数量对比。
- **数据持久化**：支持将捕获结果保存为 JSON 文件，并可重新载入进行离线分析。
- **资源监测**：集成 psutil 监测应用 CPU 与内存使用情况，支持导出资源消耗日志，方便在长时间运行（≥1 天）后评估对系统的影响。

## 环境依赖

- Python 3.9+
- Tkinter（随大多数 Python 发行版提供）
- [Scapy](https://scapy.net)
- [Matplotlib](https://matplotlib.org/)
- [psutil](https://github.com/giampaolo/psutil)

可以通过 pip 安装依赖：

```bash
pip install -r requirements.txt
```

> **注意**：捕获网络数据通常需要管理员权限（Linux 上建议以 root 运行或赋予必要的能力）。

## 使用方法

1. 安装依赖并确保具备抓包权限。
2. 在终端执行：

   ```bash
   python -m packet_capture_tool.app
   ```

3. 在 GUI 中：
   - 在顶部输入 BPF 过滤表达式（可留空）。
   - 点击 “Start Capture” 开始抓包，点击 “Stop” 停止。
   - 左侧列表展示实时捕获的报文，选中即可在右侧查看网络层、传输层逐字段解析信息。
   - “Statistics” 页签提供表格统计及 IPv6 折线 / TCP-UDP-ARP 柱状图。
   - “Resource Monitor” 页签展示运行起止时间、CPU/内存占用，并可导出日志。
   - 使用 “Save Capture” / “Load Capture” 进行数据保存与加载。

## 长时间运行建议

- 运行前选择合适的过滤规则，避免高流量导致 UI 堆积过多数据。
- 软件提供运行时长显示，可记录开始与结束时间；结合资源日志，可在运行 24 小时后分析 CPU、内存曲线，确认对系统影响较小。
- 如需进一步分析，可将保存的 JSON 报文文件导入本工具进行离线回放。

## 目录结构

```
packet_capture_tool/
├── app.py               # GUI 主程序入口
├── capture.py           # 嗅探器管理封装
├── packet_parser.py     # 报文解析逻辑
├── resource_monitor.py  # 资源监控线程
├── stats.py             # 统计与可视化数据模型
├── storage.py           # 抓包数据持久化
└── __init__.py
```

## 开发与调试

- GUI 使用 Tkinter，统计图表嵌入 Matplotlib。
- 捕获线程与 GUI 线程之间通过 `queue.Queue` 传递数据，避免线程安全问题。
- 若在无 Scapy/psutil 环境运行，将提示无法抓包或资源监控不可用。

欢迎根据实际需求扩展更多协议解析或导出格式。

