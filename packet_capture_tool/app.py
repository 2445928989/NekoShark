"""Tkinter based packet capture and analysis application."""
from __future__ import annotations


import json
import logging
import queue
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from .capture import CaptureManager, CaptureUnavailableError
from .packet_parser import ParsedPacket, parse_packet
from .resource_monitor import ResourceMonitor, ResourceSample
from .stats import TrafficStats
from .storage import load_packets, save_packets


class PacketCaptureApp(tk.Tk):
    """Main GUI application."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Packet Capture & Analysis Tool")
        self.geometry("1200x800")

        self.packet_queue: "queue.Queue[ParsedPacket]" = queue.Queue()
        self.captured_packets: List[ParsedPacket] = []
        self.resource_samples: List[ResourceSample] = []
        self.stats = TrafficStats(window=timedelta(days=1))
        self.capture_start: Optional[datetime] = None

        self.capture_manager = CaptureManager(self._on_packet_captured)
        self.resource_monitor = ResourceMonitor(self._on_resource_sample, interval=2.0)

        # 优化参数：限制UI显示、批处理、限流
        self._max_packets_display = 5000
        self._stats_update_counter = 0
        self._stats_update_interval = 10
        self._pending_ui_update = False
        self._display_offset = 0 

        self._build_ui()
        self.after(1000, self._update_uptime)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        main_pane = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main_pane.grid(row=0, column=0, sticky="nsew")

        left_frame = ttk.Frame(main_pane)
        right_frame = ttk.Frame(main_pane)
        main_pane.add(left_frame, weight=3)
        main_pane.add(right_frame, weight=5)

        # Controls
        control_frame = ttk.Frame(left_frame)
        control_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        control_frame.columnconfigure(1, weight=1)

        ttk.Label(control_frame, text="BPF Filter:").grid(row=0, column=0, sticky="w")
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var)
        filter_entry.grid(row=0, column=1, sticky="ew", padx=5)

        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=2, padx=5)
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5)

        self.save_button = ttk.Button(control_frame, text="Save Capture", command=self.save_capture)
        self.save_button.grid(row=1, column=2, padx=5, pady=5)
        self.load_button = ttk.Button(control_frame, text="Load Capture", command=self.load_capture)
        self.load_button.grid(row=1, column=3, padx=5, pady=5)

        # Packet list
        packet_frame = ttk.Frame(left_frame)
        packet_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        left_frame.rowconfigure(1, weight=1)
        packet_frame.rowconfigure(0, weight=1)
        packet_frame.columnconfigure(0, weight=1)

        columns = ("time", "summary", "protocols")
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings", height=20)
        self.packet_tree.heading("time", text="Time")
        self.packet_tree.heading("summary", text="Summary")
        self.packet_tree.heading("protocols", text="Protocols")
        self.packet_tree.column("time", width=140, anchor=tk.W)
        self.packet_tree.column("summary", width=400)
        self.packet_tree.column("protocols", width=120)
        self.packet_tree.bind("<<TreeviewSelect>>", self._on_packet_selected)

        scroll = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scroll.set)
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        # Right side notebook
        notebook = ttk.Notebook(right_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        self.details_tab = ttk.Frame(notebook)
        self.stats_tab = ttk.Frame(notebook)
        self.resource_tab = ttk.Frame(notebook)
        notebook.add(self.details_tab, text="Packet Details")
        notebook.add(self.stats_tab, text="Statistics")
        notebook.add(self.resource_tab, text="Resource Monitor")

        self._build_details_tab()
        self._build_stats_tab()
        self._build_resource_tab()

    def _build_details_tab(self) -> None:
        self.details_text = tk.Text(self.details_tab, wrap=tk.NONE, height=25)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.details_text.configure(state=tk.DISABLED)

    def _build_stats_tab(self) -> None:
        stats_top = ttk.Frame(self.stats_tab)
        stats_top.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        columns = ("protocol", "count")
        self.stats_tree = ttk.Treeview(stats_top, columns=columns, show="headings", height=6)
        self.stats_tree.heading("protocol", text="Protocol")
        self.stats_tree.heading("count", text="Packets")
        self.stats_tree.column("protocol", width=100)
        self.stats_tree.column("count", width=80, anchor=tk.E)
        self.stats_tree.pack(side=tk.LEFT, fill=tk.X, expand=False)

        stats_scroll = ttk.Scrollbar(stats_top, orient=tk.VERTICAL, command=self.stats_tree.yview)
        self.stats_tree.configure(yscrollcommand=stats_scroll.set)
        stats_scroll.pack(side=tk.LEFT, fill=tk.Y)

        figure = Figure(figsize=(6, 4), dpi=100)
        self.ax_ipv6 = figure.add_subplot(211)
        self.ax_ipv6.set_title("IPv6 Traffic Percentage (last 24h)")
        self.ax_ipv6.set_ylabel("IPv6 %")

        self.ax_bar = figure.add_subplot(212)
        self.ax_bar.set_title("TCP/UDP/ARP Distribution")
        self.ax_bar.set_ylabel("Packets")

        self.canvas = FigureCanvasTkAgg(figure, master=self.stats_tab)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _build_resource_tab(self) -> None:
        info_frame = ttk.Frame(self.resource_tab)
        info_frame.pack(fill=tk.X, padx=5, pady=5)

        self.start_time_var = tk.StringVar(value="Start time: -")
        self.uptime_var = tk.StringVar(value="Uptime: 0s")
        ttk.Label(info_frame, textvariable=self.start_time_var).pack(anchor=tk.W)
        ttk.Label(info_frame, textvariable=self.uptime_var).pack(anchor=tk.W)

        self.resource_tree = ttk.Treeview(
            self.resource_tab,
            columns=("time", "cpu", "memory"),
            show="headings",
            height=12,
        )
        self.resource_tree.heading("time", text="Timestamp")
        self.resource_tree.heading("cpu", text="CPU %")
        self.resource_tree.heading("memory", text="Memory (MB)")
        self.resource_tree.column("time", width=160)
        self.resource_tree.column("cpu", width=80, anchor=tk.E)
        self.resource_tree.column("memory", width=110, anchor=tk.E)
        self.resource_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        export_button = ttk.Button(self.resource_tab, text="Export Resource Log", command=self.export_resource_log)
        export_button.pack(pady=5)

        if not ResourceMonitor.is_available():
            ttk.Label(
                self.resource_tab,
                text="psutil 未安装，资源监控不可用",
                foreground="red",
            ).pack(pady=5)

    # ------------------------------------------------------------------ Packet handling
    def _on_packet_captured(self, packet: object) -> None:
        try:
            parsed = parse_packet(packet)
            self.packet_queue.put(parsed)
            if not self._pending_ui_update:
                self._pending_ui_update = True
                self.after(50, self._drain_packet_queue)
        except Exception:
            logging.exception("Failed to parse packet")

    def _drain_packet_queue(self) -> None:
        self._pending_ui_update = False
        updated = False
        batch_count = 0
        max_batch_size = 100
        
        while batch_count < max_batch_size:
            try:
                packet = self.packet_queue.get_nowait()
            except queue.Empty:
                break
            else:
                self.captured_packets.append(packet)
                self.stats.register(packet)
                self._stats_update_counter += 1
                batch_count += 1
                
                index = len(self.captured_packets) - 1
                # 当前UI中显示的条目数
                display_count = len(self.packet_tree.get_children())

                # 始终使用捕获包的全局索引作为 iid，这样 selection 可以直接映射到 captured_packets
                if display_count < self._max_packets_display:
                    self.packet_tree.insert(
                        "",
                        tk.END,
                        iid=str(index),
                        values=(packet.timestamp.strftime("%H:%M:%S"), packet.summary, ",".join(packet.protocols)),
                    )
                    updated = True
                else:
                    # 超过显示上限：删除最旧的显示项（Treeview 中的第一项），然后插入新项（iid 为全局索引）
                    children = self.packet_tree.get_children()
                    if children:
                        self.packet_tree.delete(children[0])
                    self.packet_tree.insert(
                        "",
                        tk.END,
                        iid=str(index),
                        values=(packet.timestamp.strftime("%H:%M:%S"), packet.summary, ",".join(packet.protocols)),
                    )
                    updated = True
        
        # 限制图表更新频率，避免频繁重绘
        if self._stats_update_counter >= self._stats_update_interval:
            self._stats_update_counter = 0
            if updated:
                self._refresh_statistics()
        
        # 如果队列中还有数据，继续处理
        if not self.packet_queue.empty():
            self._pending_ui_update = True
            self.after(50, self._drain_packet_queue)

    def _on_packet_selected(self, _event: object) -> None:
        selection = self.packet_tree.selection()
        if not selection:
            return
        idx = int(selection[0])
        packet = self.captured_packets[idx]
        self._display_packet_details(packet)

    def _display_packet_details(self, packet: ParsedPacket) -> None:
        self.details_text.configure(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)

        self.details_text.insert(tk.END, f"Captured at: {packet.timestamp}\n")
        self.details_text.insert(tk.END, f"Summary: {packet.summary}\n\n")

        self.details_text.insert(tk.END, "[Network Layer]\n")
        for key, value in packet.network_layer.items():
            self.details_text.insert(tk.END, f"  {key}: {value}\n")

        self.details_text.insert(tk.END, "\n[Transport Layer]\n")
        for key, value in packet.transport_layer.items():
            self.details_text.insert(tk.END, f"  {key}: {value}\n")

        if packet.dns_info:
            self.details_text.insert(tk.END, "\n[DNS]\n")
            for key, value in packet.dns_info.items():
                self.details_text.insert(tk.END, f"  {key}: {value}\n")

        self.details_text.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------ Capture controls
    def start_capture(self) -> None:
        filter_expr = self.filter_var.get().strip() or None
        try:
            self.capture_manager.start(filter_expr=filter_expr)
        except CaptureUnavailableError as exc:
            messagebox.showerror("Capture unavailable", str(exc))
            return
        except Exception as exc:  # pragma: no cover - safety
            messagebox.showerror("Capture error", str(exc))
            return

        self.capture_start = datetime.now()
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.start_time_var.set(f"Start time: {self.capture_start.strftime('%Y-%m-%d %H:%M:%S')}")
        self.resource_monitor.start()

    def stop_capture(self) -> None:
        logging.info("停止抓包")
        self.capture_manager.stop()
        self.resource_monitor.stop()
        self.capture_start = None
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self.uptime_var.set("Uptime: 0s")

    # ------------------------------------------------------------------ Statistics & charts
    def _refresh_statistics(self) -> None:
        # 更新表格（增量更新，避免闪烁）
        current_items = {item: self.stats_tree.item(item) for item in self.stats_tree.get_children()}
        for protocol, count in self.stats.table_rows():
            found = False
            for item_id, item_data in current_items.items():
                if item_data['values'][0] == protocol:
                    self.stats_tree.item(item_id, values=(protocol, count))
                    found = True
                    break
            if not found:
                self.stats_tree.insert("", tk.END, values=(protocol, count))

        # 更新图表
        ipv6_series = self.stats.ipv6_ratio_series()
        if ipv6_series:
            self.ax_ipv6.clear()
            self.ax_ipv6.set_title("IPv6 Traffic Percentage (last 24h)")
            self.ax_ipv6.set_ylabel("IPv6 %")
            x = [ts for ts, _ in ipv6_series]
            y = [ratio for _, ratio in ipv6_series]
            self.ax_ipv6.plot_date(x, y, linestyle="solid", marker=None)
            self.ax_ipv6.set_ylim(0, 100)
            self.ax_ipv6.grid(True, which="both", linestyle="--", alpha=0.5)

        counters = self.stats.protocol_counters()
        self.ax_bar.clear()
        self.ax_bar.set_title("TCP/UDP/ARP Distribution")
        self.ax_bar.set_ylabel("Packets")
        labels = ["TCP", "UDP", "ARP"]
        values = [counters.get(label, 0) for label in labels]
        self.ax_bar.bar(labels, values, color=["#1f77b4", "#ff7f0e", "#2ca02c"])
        self.ax_bar.grid(axis="y", linestyle="--", alpha=0.5)

        self.canvas.draw_idle()

    # ------------------------------------------------------------------ Persistence
    def save_capture(self) -> None:
        if not self.captured_packets:
            messagebox.showinfo("No data", "No packets to save yet.")
            return
        file_path = filedialog.asksaveasfilename(
            title="Save captured packets",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not file_path:
            return
        try:
            save_packets(Path(file_path), self.captured_packets)
        except Exception as exc:
            messagebox.showerror("Save error", str(exc))
        else:
            messagebox.showinfo("Saved", f"Capture saved to {file_path}")

    def load_capture(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Open capture",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not file_path:
            return
        try:
            packets = load_packets(Path(file_path))
        except Exception as exc:
            messagebox.showerror("Load error", str(exc))
            return

        self.captured_packets = packets
        self.stats.reset()
        self.packet_tree.delete(*self.packet_tree.get_children())
        # 只在UI中加载最后N个数据包
        start_idx = max(0, len(packets) - self._max_packets_display)
        for idx, packet in enumerate(packets):
            self.stats.register(packet)
            if idx >= start_idx:
                self.packet_tree.insert(
                    "",
                    tk.END,
                    iid=str(idx),
                    values=(packet.timestamp.strftime("%H:%M:%S"), packet.summary, ",".join(packet.protocols)),
                )
        self._refresh_statistics()
        messagebox.showinfo("Loaded", f"Loaded {len(packets)} packets (displaying last {min(len(packets), self._max_packets_display)})")

    # ------------------------------------------------------------------ Resource monitoring
    def _on_resource_sample(self, sample: ResourceSample) -> None:
        self.resource_samples.append(sample)
        self.after(0, lambda: self._append_resource_sample(sample))

    def _append_resource_sample(self, sample: ResourceSample) -> None:
        timestamp = sample.timestamp.strftime("%H:%M:%S")
        self.resource_tree.insert("", tk.END, values=(timestamp, f"{sample.cpu_percent:.2f}", f"{sample.memory_mb:.2f}"))
        # Limit to last 200 samples in UI
        children = self.resource_tree.get_children()
        if len(children) > 200:
            self.resource_tree.delete(children[0])

    def export_resource_log(self) -> None:
        if not self.resource_samples:
            messagebox.showinfo("No samples", "No resource samples captured yet.")
            return
        file_path = filedialog.asksaveasfilename(
            title="Export resource usage",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not file_path:
            return
        try:
            payload = [
                {
                    "timestamp": sample.timestamp.isoformat(),
                    "cpu_percent": sample.cpu_percent,
                    "memory_mb": sample.memory_mb,
                }
                for sample in self.resource_samples
            ]
            Path(file_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as exc:
            messagebox.showerror("Export error", str(exc))
        else:
            messagebox.showinfo("Exported", f"Resource log saved to {file_path}")

    def _update_uptime(self) -> None:
        if self.capture_start:
            delta = datetime.now() - self.capture_start
            self.uptime_var.set(f"Uptime: {str(delta).split('.')[0]}")
        self.after(1000, self._update_uptime)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = PacketCaptureApp()
    app.mainloop()


if __name__ == "__main__":
    main()

