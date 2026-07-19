"""
ATP v1.6.1 — PySide6 Dashboard.
Real-time monitoring GUI with tabs, charts, and thread-safe backend integration.
"""

from __future__ import annotations

import os
import sys
import time
import json
import logging
import threading
import asyncio
from collections import deque
from typing import Optional

from PySide6.QtCore import (
    Qt, QThread, Signal, QObject, QTimer, QDateTime,
)
from PySide6.QtGui import (
    QAction, QIcon, QColor, QPalette, QFont, QBrush,
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QPushButton, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QToolBar, QStatusBar, QMenu,
    QMenuBar, QMessageBox, QFrame, QGroupBox, QSplitter,
    QLineEdit, QComboBox, QTextEdit, QSizePolicy,
)

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib

matplotlib.use("Qt5Agg")

from monitor import (
    Monitor, MonitorSignals,
    CONNECTION_OPEN, CONNECTION_CLOSE,
    HANDSHAKE_START, HANDSHAKE_COMPLETE, HANDSHAKE_FAILED,
    FRAME_SENT, FRAME_RECEIVED,
    TASK_START, TASK_COMPLETE, TASK_ERROR,
    MCC_VERIFICATION_SUCCESS, MCC_VERIFICATION_FAILED,
    BINDING_SUCCESS, BINDING_FAILED,
    DEEPSEEK_CALL_START, DEEPSEEK_CALL_END,
    RATE_LIMIT_HIT, BAN_TRIGGERED,
    ERROR_OCCURRED,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  Backend threads
# ═══════════════════════════════════════════════════════════════════════════════

class ServerThread(QThread):
    """Runs the ATP server in its own asyncio event loop."""

    started = Signal()
    stopped = Signal()
    error_occurred = Signal(str)

    def __init__(self, monitor: Monitor, parent=None):
        super().__init__(parent)
        self.monitor = monitor
        self._server = None
        self._loop = None

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        from server import ATPServer
        self._server = ATPServer(monitor=self.monitor)
        self._task = self._loop.create_task(self._server.start())
        self.started.emit()
        try:
            self._loop.run_forever()
        except Exception as exc:
            if not isinstance(exc, RuntimeError):
                self.error_occurred.emit(str(exc))
        finally:
            # Cancel any remaining tasks
            for t in asyncio.all_tasks(self._loop):
                t.cancel()
            self._loop.run_until_complete(
                asyncio.sleep(0)
            ) if asyncio.all_tasks(self._loop) else None
            self._loop.close()
            self.stopped.emit()

    async def stop(self):
        if self._server:
            await self._server.stop()
        if self._loop:
            self._loop.stop()

    def request_stop(self):
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.stop(), self._loop)


class ClientThread(QThread):
    """Runs the ATP client in its own asyncio event loop."""

    connected = Signal()
    disconnected = Signal()
    error_occurred = Signal(str)
    task_response = Signal(object)

    def __init__(self, monitor: Monitor, parent=None):
        super().__init__(parent)
        self.monitor = monitor
        self._client = None
        self._loop = None

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        from client import ATPClient
        self._client = ATPClient(monitor=self.monitor)
        try:
            ok = self._loop.run_until_complete(self._client.connect())
            if ok:
                self.connected.emit()
                # Keep the loop running for future tasks
                self._loop.run_forever()
            else:
                self.error_occurred.emit("Handshake failed")
        except Exception as exc:
            self.error_occurred.emit(str(exc))
        finally:
            self.disconnected.emit()

    async def send_task_async(self, task_type: str, payload: str):
        if self._client:
            resp = await self._client.send_task(task_type, payload)
            if resp:
                self.task_response.emit(resp)

    def send_task(self, task_type: str, payload: str):
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self.send_task_async(task_type, payload), self._loop
            )

    def request_stop(self):
        if self._loop and self._loop.is_running():
            async def _stop():
                if self._client:
                    await self._client.disconnect()
                self._loop.stop()
            asyncio.run_coroutine_threadsafe(_stop(), self._loop)


class ClientThread2(QThread):
    """Runs a SECOND ATP client (different identity) in its own asyncio event loop."""

    connected = Signal()
    disconnected = Signal()
    error_occurred = Signal(str)
    task_response = Signal(object)

    def __init__(self, monitor: Monitor, parent=None):
        super().__init__(parent)
        self.monitor = monitor
        self._client = None
        self._loop = None

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        from client import ATPClient
        from agent import AgentIdentity
        self._client = ATPClient(monitor=self.monitor)
        self._client.identity = AgentIdentity(agent_name="atp-client-2")
        try:
            ok = self._loop.run_until_complete(self._client.connect())
            if ok:
                self.connected.emit()
                self._loop.run_forever()
            else:
                self.error_occurred.emit("Handshake failed (Client 2)")
        except Exception as exc:
            self.error_occurred.emit(str(exc))
        finally:
            self.disconnected.emit()

    async def send_task_async(self, task_type: str, payload: str):
        if self._client:
            resp = await self._client.send_task(task_type, payload)
            if resp:
                self.task_response.emit(resp)

    def send_task(self, task_type: str, payload: str):
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self.send_task_async(task_type, payload), self._loop
            )

    def request_stop(self):
        if self._loop and self._loop.is_running():
            async def _stop():
                if self._client:
                    await self._client.disconnect()
                self._loop.stop()
            asyncio.run_coroutine_threadsafe(_stop(), self._loop)


# ═══════════════════════════════════════════════════════════════════════════════
#  Matplotlib chart canvas
# ═══════════════════════════════════════════════════════════════════════════════

class TrafficChart(FigureCanvas):
    """Live-updating line chart of frame traffic over time."""

    def __init__(self, parent=None):
        self.fig = Figure(figsize=(5, 3), dpi=100, facecolor="#1e1e2e")
        super().__init__(self.fig)
        self.setParent(parent)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor("#2a2a3e")
        self.ax.tick_params(colors="#cdd6f4", labelsize=8)
        self.ax.spines["bottom"].set_color("#45475a")
        self.ax.spines["left"].set_color("#45475a")
        self.ax.spines["top"].set_visible(False)
        self.ax.spines["right"].set_visible(False)
        self.ax.set_xlabel("Time (s)", color="#cdd6f4", fontsize=9)
        self.ax.set_ylabel("Frames / sec", color="#cdd6f4", fontsize=9)
        self.ax.set_title("Frame Traffic", color="#cdd6f4", fontsize=10, fontweight="bold")

        # Data: rolling 60 seconds
        self._timestamps: deque[float] = deque(maxlen=60)
        self._sent_counts: deque[int] = deque(maxlen=60)
        self._recv_counts: deque[int] = deque(maxlen=60)

        self._sent_line, = self.ax.plot([], [], color="#89b4fa", label="Sent", linewidth=1.5)
        self._recv_line, = self.ax.plot([], [], color="#a6e3a1", label="Received", linewidth=1.5)
        self.ax.legend(loc="upper left", fontsize=8, facecolor="#313244", labelcolor="#cdd6f4")
        self.fig.tight_layout()

    def update_data(self, sent: int, recv: int):
        now = time.time()
        self._timestamps.append(now)
        self._sent_counts.append(sent)
        self._recv_counts.append(recv)

        if len(self._timestamps) < 2:
            return

        t0 = self._timestamps[0]
        ts = [t - t0 for t in self._timestamps]
        self._sent_line.set_data(ts, list(self._sent_counts))
        self._recv_line.set_data(ts, list(self._recv_counts))
        self.ax.relim()
        self.ax.autoscale_view()
        self.draw_idle()


# ═══════════════════════════════════════════════════════════════════════════════
#  Metric Card (small frame with a label + value)
# ═══════════════════════════════════════════════════════════════════════════════

class MetricCard(QFrame):
    """A small card showing one metric value."""

    def __init__(self, title: str, initial: str = "0", color: str = "#89b4fa",
                 parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet(f"""
            MetricCard {{
                background-color: #313244;
                border: 1px solid #45475a;
                border-radius: 8px;
                padding: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #a6adc8; font-size: 11px; font-weight: bold;")
        self.title_label.setAlignment(Qt.AlignCenter)

        self.value_label = QLabel(initial)
        self.value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
        self.value_label.setAlignment(Qt.AlignCenter)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

    def set_value(self, value: str):
        self.value_label.setText(value)


# ═══════════════════════════════════════════════════════════════════════════════
#  Main Window
# ═══════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    """ATP Dashboard — PySide6 main window."""

    def __init__(self, monitor: Monitor):
        super().__init__()
        self.monitor = monitor
        self._server_thread: Optional[ServerThread] = None
        self._client_thread: Optional[ClientThread] = None
        self._client2_thread: Optional[ClientThread2] = None
        self._server_running = False
        self._client_running = False
        self._client2_running = False

        # Rolling counters for chart
        self._frame_sent_count = 0
        self._frame_recv_count = 0
        self._last_chart_update = time.time()

        self._setup_ui()
        self._connect_signals()
        self._start_refresh_timers()

        self.setWindowTitle("ATP v1.6.1 Dashboard")
        self.resize(1200, 800)

        # Apply dark theme
        self._apply_dark_theme()

    # ── UI setup ─────────────────────────────────────────────────────────

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Menu bar ─────────────────────────────────────────────────────
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = menubar.addMenu("&View")
        reset_action = QAction("&Reset Layout", self)
        reset_action.triggered.connect(self._reset_layout)
        view_menu.addAction(reset_action)

        help_menu = menubar.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

        # ── Toolbar ──────────────────────────────────────────────────────
        toolbar = QToolBar("Controls")
        toolbar.setStyleSheet("""
            QToolBar { background-color: #181825; border-bottom: 1px solid #313244; padding: 4px; }
            QPushButton { padding: 6px 14px; border-radius: 4px; font-weight: bold; }
        """)
        self.addToolBar(toolbar)

        self.btn_server = QPushButton("Start Server")
        self.btn_server.setStyleSheet("background-color: #89b4fa; color: #1e1e2e;")
        self.btn_server.clicked.connect(self._toggle_server)

        self.btn_client = QPushButton("Start Client")
        self.btn_client.setStyleSheet("background-color: #a6e3a1; color: #1e1e2e;")
        self.btn_client.clicked.connect(self._toggle_client)

        self.btn_client2 = QPushButton("Start Client 2")
        self.btn_client2.setStyleSheet("background-color: #cba6f7; color: #1e1e2e;")
        self.btn_client2.clicked.connect(self._toggle_client2)

        self.btn_task = QPushButton("Send Task")
        self.btn_task.setStyleSheet("background-color: #f9e2af; color: #1e1e2e;")
        self.btn_task.clicked.connect(self._send_test_task)
        self.btn_task.setEnabled(False)

        self.btn_task2 = QPushButton("Send Task 2")
        self.btn_task2.setStyleSheet("background-color: #f9e2af; color: #1e1e2e;")
        self.btn_task2.clicked.connect(self._send_test_task2)
        self.btn_task2.setEnabled(False)

        self.btn_clear = QPushButton("Clear Logs")
        self.btn_clear.setStyleSheet("background-color: #f38ba8; color: #1e1e2e;")
        self.btn_clear.clicked.connect(self._clear_logs)

        # Task input
        self.task_input = QLineEdit()
        self.task_input.setPlaceholderText("Enter task prompt for DeepSeek...")
        self.task_input.setStyleSheet("""
            QLineEdit {
                background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                border-radius: 4px; padding: 4px 8px; min-width: 300px;
            }
        """)
        self.task_input.setText("Spiega il concetto di agenti autonomi basati su LLM a una platea di accademici. Sii preciso e tecnico.")

        toolbar.addWidget(self.btn_server)
        toolbar.addWidget(self.btn_client)
        toolbar.addWidget(self.btn_client2)
        toolbar.addWidget(self.btn_task)
        toolbar.addWidget(self.btn_task2)
        toolbar.addWidget(self.btn_clear)
        toolbar.addSeparator()
        toolbar.addWidget(self.task_input)

        # ── Tab widget ───────────────────────────────────────────────────
        body_splitter = QSplitter(Qt.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: none; background-color: #1e1e2e; }
            QTabBar::tab { background: #313244; color: #a6adc8; padding: 8px 16px;
                           border-top-left-radius: 6px; border-top-right-radius: 6px; }
            QTabBar::tab:selected { background: #45475a; color: #cdd6f4; font-weight: bold; }
        """)

        self.tabs.addTab(self._build_overview_tab(), "Overview")
        self.tabs.addTab(self._build_traffic_tab(), "Traffic")
        self.tabs.addTab(self._build_connections_tab(), "Connections")
        self.tabs.addTab(self._build_agents_tab(), "Agents")
        self.tabs.addTab(self._build_tasks_tab(), "Tasks")

        left_layout.addWidget(self.tabs)

        # Right panel — chart
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(4, 4, 4, 4)
        chart_group = QGroupBox("Traffic Chart")
        chart_group.setStyleSheet("""
            QGroupBox { color: #cdd6f4; font-weight: bold; border: 1px solid #45475a;
                        border-radius: 8px; margin-top: 12px; padding-top: 16px; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; }
        """)
        chart_layout = QVBoxLayout(chart_group)
        self.chart = TrafficChart()
        chart_layout.addWidget(self.chart)
        right_layout.addWidget(chart_group)

        body_splitter.addWidget(left_panel)
        body_splitter.addWidget(right_panel)
        body_splitter.setSizes([600, 400])
        body_splitter.setStyleSheet("QSplitter::handle { background-color: #313244; width: 2px; }")

        main_layout.addWidget(body_splitter, stretch=1)

        # ── Status bar ───────────────────────────────────────────────────
        self.status = QStatusBar()
        self.status.setStyleSheet("""
            QStatusBar { background-color: #181825; color: #a6adc8;
                         border-top: 1px solid #313244; padding: 2px; }
        """)
        self.status_label = QLabel("Ready")
        self.status_event = QLabel("")
        self.status.addWidget(self.status_label, stretch=1)
        self.status.addPermanentWidget(self.status_event)
        self.setStatusBar(self.status)

    def _build_overview_tab(self) -> QWidget:
        tab = QWidget()
        layout = QGridLayout(tab)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        self.metric_tasks_sent = MetricCard("Tasks Sent", "#89b4fa")
        self.metric_tasks_recv = MetricCard("Tasks Received", "#a6e3a1")
        self.metric_tasks_err = MetricCard("Task Errors", "#f38ba8")
        self.metric_latency = MetricCard("Avg Latency (ms)", "0", "#f9e2af")
        self.metric_connections = MetricCard("Active Connections", "0", "#cba6f7")
        self.metric_errors = MetricCard("Total Errors", "0", "#f38ba8")
        self.metric_rate = MetricCard("Rate Limit Hits", "0", "#fab387")
        self.metric_bans = MetricCard("Bans", "0", "#eba0ac")

        layout.addWidget(self.metric_tasks_sent, 0, 0)
        layout.addWidget(self.metric_tasks_recv, 0, 1)
        layout.addWidget(self.metric_tasks_err, 0, 2)
        layout.addWidget(self.metric_latency, 0, 3)
        layout.addWidget(self.metric_connections, 1, 0)
        layout.addWidget(self.metric_errors, 1, 1)
        layout.addWidget(self.metric_rate, 1, 2)
        layout.addWidget(self.metric_bans, 1, 3)

        # Event log pane at bottom
        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        self.event_log.setMaximumHeight(200)
        self.event_log.setStyleSheet("""
            QTextEdit {
                background-color: #11111b; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px; padding: 4px;
            }
        """)
        layout.addWidget(self.event_log, 2, 0, 1, 4)

        return tab

    def _build_traffic_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)

        # Filter bar
        filter_bar = QHBoxLayout()
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("color: #cdd6f4; font-weight: bold;")
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "TASK_REQUEST", "TASK_RESPONSE",
                                     "TASK_ACK", "MCC_BIND_REQUEST",
                                     "MCC_BIND_RESPONSE", "MCC_BIND_CONFIRM",
                                     "VERSION_PROPOSE", "VERSION_ACK",
                                     "CAPABILITY_EXCHANGE", "ERROR"])
        self.filter_combo.setStyleSheet("""
            QComboBox { background-color: #313244; color: #cdd6f4;
                        border: 1px solid #45475a; border-radius: 4px; padding: 4px; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background-color: #313244; color: #cdd6f4;
                                          selection-background-color: #45475a; }
        """)
        self.filter_combo.currentTextChanged.connect(self._apply_traffic_filter)
        filter_bar.addWidget(filter_label)
        filter_bar.addWidget(self.filter_combo)
        filter_bar.addStretch()
        layout.addLayout(filter_bar)

        # Traffic table
        self.traffic_table = QTableWidget(0, 5)
        self.traffic_table.setHorizontalHeaderLabels(["Time", "Type", "Direction", "Details", "Status"])
        self.traffic_table.horizontalHeader().setStretchLastSection(True)
        self.traffic_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.traffic_table.setAlternatingRowColors(True)
        self.traffic_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e2e; color: #cdd6f4; gridline-color: #313244;
                border: 1px solid #45475a; border-radius: 6px;
                font-size: 11px;
            }
            QTableWidget::item { padding: 4px; }
            QTableWidget::item:selected { background-color: #45475a; }
            QHeaderView::section { background-color: #313244; color: #cdd6f4;
                                   border: none; padding: 6px; font-weight: bold; }
        """)
        self.traffic_table.setColumnWidth(0, 160)
        self.traffic_table.setColumnWidth(1, 120)
        self.traffic_table.setColumnWidth(2, 80)
        self.traffic_table.setColumnWidth(3, 250)
        self.traffic_table.setColumnWidth(4, 80)
        layout.addWidget(self.traffic_table)

        return tab

    def _build_connections_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)

        self.conn_table = QTableWidget(0, 5)
        self.conn_table.setHorizontalHeaderLabels(["Conn ID", "Agent", "MCC Hash", "State", "Last Event"])
        self.conn_table.horizontalHeader().setStretchLastSection(True)
        self.conn_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.conn_table.setAlternatingRowColors(True)
        self.conn_table.setStyleSheet(self.traffic_table.styleSheet())
        layout.addWidget(self.conn_table)

        return tab

    def _build_agents_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)

        # Summary cards at top
        summary = QHBoxLayout()
        self.agent_count_label = QLabel("Registered agents: 0")
        self.agent_count_label.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold; padding: 4px;")
        self.agent_bound_label = QLabel("Bound: 0")
        self.agent_bound_label.setStyleSheet("color: #a6e3a1; font-size: 14px; font-weight: bold; padding: 4px;")
        summary.addWidget(self.agent_count_label)
        summary.addWidget(self.agent_bound_label)
        summary.addStretch()
        layout.addLayout(summary)

        # Agent table
        self.agent_table = QTableWidget(0, 7)
        self.agent_table.setHorizontalHeaderLabels([
            "Agent Name", "Role", "X25519 PK", "Ed25519 PK",
            "MCC Root Hash", "Status", "Last Seen"
        ])
        self.agent_table.horizontalHeader().setStretchLastSection(True)
        self.agent_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.agent_table.setAlternatingRowColors(True)
        self.agent_table.setColumnWidth(0, 140)
        self.agent_table.setColumnWidth(1, 70)
        self.agent_table.setColumnWidth(2, 130)
        self.agent_table.setColumnWidth(3, 130)
        self.agent_table.setColumnWidth(4, 130)
        self.agent_table.setColumnWidth(5, 100)
        self.agent_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e2e; color: #cdd6f4; gridline-color: #313244;
                border: 1px solid #45475a; border-radius: 6px; font-size: 11px;
            }
            QTableWidget::item { padding: 4px; }
            QTableWidget::item:selected { background-color: #45475a; }
            QHeaderView::section { background-color: #313244; color: #cdd6f4;
                                   border: none; padding: 6px; font-weight: bold; }
        """)
        layout.addWidget(self.agent_table)

        # Legend
        legend = QLabel(
            "🟢 initialized  🟡 connecting  🔵 bound  ⚫ inactive  🔴 error"
        )
        legend.setStyleSheet("color: #a6adc8; font-size: 11px; padding: 4px;")
        layout.addWidget(legend)

        return tab

    def _build_tasks_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)

        # Summary bar
        summary = QHBoxLayout()
        self.task_count_label = QLabel("Tasks: 0")
        self.task_count_label.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold; padding: 4px;")
        self.task_ok_label = QLabel("Completed: 0")
        self.task_ok_label.setStyleSheet("color: #a6e3a1; font-size: 14px; font-weight: bold; padding: 4px;")
        self.task_err_label = QLabel("Errors: 0")
        self.task_err_label.setStyleSheet("color: #f38ba8; font-size: 14px; font-weight: bold; padding: 4px;")
        summary.addWidget(self.task_count_label)
        summary.addWidget(self.task_ok_label)
        summary.addWidget(self.task_err_label)
        summary.addStretch()
        layout.addLayout(summary)

        # Filter bar
        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel("Agent:"))
        self.task_filter_agent = QComboBox()
        self.task_filter_agent.addItems(["All", "atp-server", "atp-client", "atp-client-2"])
        self.task_filter_agent.setStyleSheet("""
            QComboBox { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                       border-radius: 4px; padding: 2px 6px; }
        """)
        self.task_filter_agent.currentTextChanged.connect(self._apply_task_filter)
        filter_bar.addWidget(self.task_filter_agent)
        filter_bar.addWidget(QLabel("Status:"))
        self.task_filter_status = QComboBox()
        self.task_filter_status.addItems(["All", "completed", "error"])
        self.task_filter_status.setStyleSheet(self.task_filter_agent.styleSheet())
        self.task_filter_status.currentTextChanged.connect(self._apply_task_filter)
        filter_bar.addWidget(self.task_filter_status)
        filter_bar.addWidget(QLabel("Dir:"))
        self.task_filter_dir = QComboBox()
        self.task_filter_dir.addItems(["All", "sent", "received"])
        self.task_filter_dir.setStyleSheet(self.task_filter_agent.styleSheet())
        self.task_filter_dir.currentTextChanged.connect(self._apply_task_filter)
        filter_bar.addWidget(self.task_filter_dir)
        filter_bar.addStretch()
        layout.addLayout(filter_bar)

        # Task table — shows request, response, status, latency, direction
        self.task_table = QTableWidget(0, 8)
        self.task_table.setHorizontalHeaderLabels([
            "Time", "Agent", "Type", "Dir", "Request",
            "Response", "ms", "Status"
        ])
        self.task_table.cellClicked.connect(self._on_task_clicked)
        self.task_table.horizontalHeader().setStretchLastSection(False)
        self.task_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.task_table.setAlternatingRowColors(True)
        self.task_table.setColumnWidth(0, 70)
        self.task_table.setColumnWidth(1, 100)
        self.task_table.setColumnWidth(2, 90)
        self.task_table.setColumnWidth(3, 35)
        self.task_table.setColumnWidth(4, 180)
        self.task_table.setColumnWidth(5, 300)
        self.task_table.setColumnWidth(6, 50)
        self.task_table.setColumnWidth(7, 70)
        self.task_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e2e; color: #cdd6f4; gridline-color: #313244;
                border: 1px solid #45475a; border-radius: 6px; font-size: 11px;
            }
            QTableWidget::item { padding: 4px; }
            QTableWidget::item:selected { background-color: #45475a; }
            QHeaderView::section { background-color: #313244; color: #cdd6f4;
                                   border: none; padding: 6px; font-weight: bold; }
        """)
        layout.addWidget(self.task_table)
        return tab

    # ── Signal connections ───────────────────────────────────────────────

    def _connect_signals(self):
        self.monitor._qt_signals.event_received.connect(self._on_event_received)

    def _start_refresh_timers(self):
        # Refresh metrics every 500 ms
        self._metric_timer = QTimer()
        self._metric_timer.timeout.connect(self._refresh_metrics)
        self._metric_timer.start(500)

        # Refresh connections every second
        self._conn_timer = QTimer()
        self._conn_timer.timeout.connect(self._refresh_connections)
        self._conn_timer.start(1000)

        # Refresh agents every second
        self._agent_timer = QTimer()
        self._agent_timer.timeout.connect(self._refresh_agents)
        self._agent_timer.start(1000)

        # Refresh tasks every second
        self._task_timer = QTimer()
        self._task_timer.timeout.connect(self._refresh_tasks)
        self._task_timer.start(1000)

        # Update chart every second
        self._chart_timer = QTimer()
        self._chart_timer.timeout.connect(self._update_chart)
        self._chart_timer.start(1000)

    # ── Theme ─────────────────────────────────────────────────────────────

    def _apply_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#1e1e2e"))
        palette.setColor(QPalette.WindowText, QColor("#cdd6f4"))
        palette.setColor(QPalette.Base, QColor("#181825"))
        palette.setColor(QPalette.Text, QColor("#cdd6f4"))
        palette.setColor(QPalette.Button, QColor("#313244"))
        palette.setColor(QPalette.ButtonText, QColor("#cdd6f4"))
        palette.setColor(QPalette.Highlight, QColor("#45475a"))
        palette.setColor(QPalette.HighlightedText, QColor("#cdd6f4"))
        self.setPalette(palette)
        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e2e; }
            QWidget { background-color: #1e1e2e; color: #cdd6f4; }
            QLabel { background: transparent; }
        """)

    # ── Slot: event received from monitor ────────────────────────────────

    def _on_event_received(self, event: dict):
        et = event["type"]
        ts = time.strftime("%H:%M:%S", time.localtime(event["timestamp"]))
        data = event.get("data", {})

        # Update status bar
        self.status_event.setText(f"Last: {et} @ {ts}")

        # Update event log
        detail = json.dumps(data, default=str)[:120]
        self.event_log.append(f"[{ts}] {et}: {detail}")

        # Update traffic table
        if et in (FRAME_SENT, FRAME_RECEIVED):
            direction = "OUT" if et == FRAME_SENT else "IN"
            ft = data.get("frame_name", f"0x{data.get('frame_type','?'):02x}")

            # Apply filter
            current_filter = self.filter_combo.currentText()
            if current_filter != "All" and ft != current_filter:
                return

            row = self.traffic_table.rowCount()
            self.traffic_table.insertRow(row)

            self.traffic_table.setItem(row, 0, QTableWidgetItem(ts))
            self.traffic_table.setItem(row, 1, QTableWidgetItem(ft))
            self.traffic_table.setItem(row, 2, QTableWidgetItem(direction))
            self.traffic_table.setItem(row, 3, QTableWidgetItem(
                data.get("conn_id", "")[:8]
            ))
            status_item = QTableWidgetItem("OK")
            status_item.setForeground(QBrush(QColor("#a6e3a1")))
            self.traffic_table.setItem(row, 4, status_item)

            # Keep table manageable
            while self.traffic_table.rowCount() > 1000:
                self.traffic_table.removeRow(0)

            # Update rolling counters
            if et == FRAME_SENT:
                self._frame_sent_count += 1
            else:
                self._frame_recv_count += 1

        # Track errors in red
        if et == ERROR_OCCURRED:
            self._log_error(event)

    def _log_error(self, event: dict):
        data = event.get("data", {})
        msg = data.get("error_message", "Unknown error")
        code = data.get("error_code", "?")
        ts = time.strftime("%H:%M:%S", time.localtime(event["timestamp"]))
        self.event_log.append(f"[{ts}] ERROR 0x{code:02x}: {msg}")

    def _apply_traffic_filter(self, *_):
        # Simple: just update the table based on filter
        # Re-render from events
        self.traffic_table.setRowCount(0)
        events = self.monitor.get_events(200)
        current_filter = self.filter_combo.currentText()
        for ev in reversed(events):
            if ev["type"] not in (FRAME_SENT, FRAME_RECEIVED):
                continue
            data = ev.get("data", {})
            ft = data.get("frame_name", "")
            if current_filter != "All" and ft != current_filter:
                continue
            row = self.traffic_table.rowCount()
            self.traffic_table.insertRow(row)
            direction = "OUT" if ev["type"] == FRAME_SENT else "IN"
            ts = time.strftime("%H:%M:%S", time.localtime(ev["timestamp"]))
            self.traffic_table.setItem(row, 0, QTableWidgetItem(ts))
            self.traffic_table.setItem(row, 1, QTableWidgetItem(ft))
            self.traffic_table.setItem(row, 2, QTableWidgetItem(direction))
            self.traffic_table.setItem(row, 3, QTableWidgetItem(data.get("conn_id", "")[:8]))
            self.traffic_table.setItem(row, 4, QTableWidgetItem("OK"))

    # ── Periodic refreshes ───────────────────────────────────────────────

    def _refresh_metrics(self):
        metrics = self.monitor.get_metrics()
        self.metric_tasks_sent.set_value(str(metrics["tasks_sent"]))
        self.metric_tasks_recv.set_value(str(metrics["tasks_received"]))
        self.metric_tasks_err.set_value(str(metrics["tasks_failed"]))
        self.metric_latency.set_value(f'{metrics["avg_latency_ms"]:.1f}')
        self.metric_connections.set_value(str(metrics["active_connections"]))
        self.metric_errors.set_value(str(metrics["errors_count"]))
        self.metric_rate.set_value(str(metrics["rate_limit_hits"]))
        self.metric_bans.set_value(str(metrics["ban_count"]))

    def _refresh_connections(self):
        conns = self.monitor.get_connections()
        self.conn_table.setRowCount(0)
        for c in conns:
            row = self.conn_table.rowCount()
            self.conn_table.insertRow(row)
            self.conn_table.setItem(row, 0, QTableWidgetItem(c.get("conn_id", "")[:8]))
            self.conn_table.setItem(row, 1, QTableWidgetItem(c.get("agent", "?")))
            self.conn_table.setItem(row, 2, QTableWidgetItem(c.get("mcc_hash", "")[:12]))
            state = c.get("state", "?")
            state_item = QTableWidgetItem(state)
            if state == "BOUND":
                state_item.setForeground(QBrush(QColor("#a6e3a1")))
            elif state == "CLOSED":
                state_item.setForeground(QBrush(QColor("#f38ba8")))
            elif state == "CONNECTED":
                state_item.setForeground(QBrush(QColor("#f9e2af")))
            self.conn_table.setItem(row, 3, state_item)
            self.conn_table.setItem(row, 4, QTableWidgetItem(c.get("last_event", "")))

    def _refresh_agents(self):
        agents = self.monitor.get_agents()
        self.agent_table.setRowCount(0)
        bound_count = 0
        for a in agents:
            row = self.agent_table.rowCount()
            self.agent_table.insertRow(row)
            self.agent_table.setItem(row, 0, QTableWidgetItem(a.get("name", "")))
            self.agent_table.setItem(row, 1, QTableWidgetItem(a.get("role", "")))
            self.agent_table.setItem(row, 2, QTableWidgetItem(a.get("x25519_pk", "")))
            self.agent_table.setItem(row, 3, QTableWidgetItem(a.get("ed25519_pk", "")))
            self.agent_table.setItem(row, 4, QTableWidgetItem(a.get("mcc_hash", "")))
            status = a.get("status", "inactive")
            status_item = QTableWidgetItem(status)
            if status == "bound":
                status_item.setForeground(QBrush(QColor("#89b4fa")))
                bound_count += 1
            elif status == "initialized":
                status_item.setForeground(QBrush(QColor("#a6e3a1")))
            elif status == "inactive":
                status_item.setForeground(QBrush(QColor("#585b70")))
            else:
                status_item.setForeground(QBrush(QColor("#f38ba8")))
            self.agent_table.setItem(row, 5, status_item)
            last_seen = a.get("last_seen", 0)
            if last_seen:
                ts = __import__("time").strftime("%H:%M:%S", __import__("time").localtime(last_seen))
            else:
                ts = "-"
            self.agent_table.setItem(row, 6, QTableWidgetItem(ts))

        self.agent_count_label.setText(f"Registered agents: {len(agents)}")
        self.agent_bound_label.setText(f"Bound: {bound_count}")

    def _refresh_tasks(self):
        tasks = self.monitor.get_tasks(200)
        self.task_table.setRowCount(0)
        # Read current filters
        agent_filter = self.task_filter_agent.currentText()
        status_filter = self.task_filter_status.currentText()
        dir_filter = self.task_filter_dir.currentText()
        ok_count = 0
        err_count = 0
        for t in reversed(tasks):
            # Apply filters
            if agent_filter != "All" and t.get("agent") != agent_filter:
                continue
            if status_filter != "All" and t.get("status") != status_filter:
                continue
            if dir_filter != "All" and t.get("direction") != dir_filter:
                continue
            row = self.task_table.rowCount()
            self.task_table.insertRow(row)
            ts = time.strftime("%H:%M:%S", time.localtime(t.get("timestamp", 0)))
            self.task_table.setItem(row, 0, QTableWidgetItem(ts))
            self.task_table.setItem(row, 1, QTableWidgetItem(t.get("agent", "")))
            self.task_table.setItem(row, 2, QTableWidgetItem(t.get("task_type", "")))
            self.task_table.setItem(row, 3, QTableWidgetItem(t.get("direction", "")))
            self.task_table.setItem(row, 4, QTableWidgetItem(t.get("request", "")[:80]))
            # Parse JSON-wrapped response to extract actual result text
            raw = t.get("response", "")
            response_text = self._parse_task_response(raw)[:300]
            self.task_table.setItem(row, 5, QTableWidgetItem(response_text))
            lat = t.get("latency_ms", 0)
            self.task_table.setItem(row, 6, QTableWidgetItem(str(lat) if lat else "-"))
            status = t.get("status", "")
            status_item = QTableWidgetItem(status)
            if status == "completed":
                status_item.setForeground(QBrush(QColor("#a6e3a1")))
                ok_count += 1
            elif status == "error":
                status_item.setForeground(QBrush(QColor("#f38ba8")))
                err_count += 1
            self.task_table.setItem(row, 7, status_item)

        total = len(tasks)
        self.task_count_label.setText(f"Tasks: {total}")
        self.task_ok_label.setText(f"Completed: {ok_count}")
        self.task_err_label.setText(f"Errors: {err_count}")

    def _on_task_clicked(self, row: int, col: int):
        """Show full task response in the event log when a task row is clicked."""
        response_item = self.task_table.item(row, 5)  # Response column
        request_item = self.task_table.item(row, 4)   # Request column
        if response_item and request_item:
            self.event_log.append(
                f"\n{'='*60}\n"
                f"[TASK DETAIL] Request: {request_item.text()}\n"
                f"{'='*60}\n"
                f"Response:\n{response_item.text()}\n"
                f"{'='*60}\n"
            )

    def _apply_task_filter(self):
        """Store current filter selections (applied in _refresh_tasks)."""
        pass  # filters are applied in _refresh_tasks by reading the combo boxes

    @staticmethod
    def _parse_task_response(raw: str) -> str:
        """Extract clean text from JSON-wrapped task response."""
        if not raw:
            return ""
        # Try JSON parse: {"result": "...", ...} or {"echo": "...", ...} or {"error": "..."}
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                for key in ("result", "echo", "error", "message"):
                    if key in obj:
                        return str(obj[key])
                return str(obj)
        except (json.JSONDecodeError, TypeError):
            pass
        return raw

    def _update_chart(self):
        # Compute per-second rates
        now = time.time()
        elapsed = now - self._last_chart_update
        if elapsed < 0.5:
            return
        sent_rate = int(self._frame_sent_count / max(elapsed, 0.001))
        recv_rate = int(self._frame_recv_count / max(elapsed, 0.001))
        self.chart.update_data(sent_rate, recv_rate)
        self._frame_sent_count = 0
        self._frame_recv_count = 0
        self._last_chart_update = now

    # ── Actions ──────────────────────────────────────────────────────────

    def _toggle_server(self):
        if self._server_running:
            if self._server_thread:
                self._server_thread.request_stop()
                self._server_thread.wait(3000)
            self._server_running = False
            self.btn_server.setText("Start Server")
            self.btn_server.setStyleSheet("background-color: #89b4fa; color: #1e1e2e;")
            self.status_label.setText("Server stopped")
            # Also disconnect any running clients (prevents zombie SSL connections)
            if self._client_running:
                self._stop_client()
            if self._client2_running:
                self._stop_client2()
        else:
            self._server_thread = ServerThread(self.monitor)
            self._server_thread.started.connect(
                lambda: self.status_label.setText("Server running on 127.0.0.1:8443")
            )
            self._server_thread.error_occurred.connect(
                lambda err: self.status_label.setText(f"Server error: {err}")
            )
            self._server_thread.start()
            self._server_running = True
            self.btn_server.setText("Stop Server")
            self.btn_server.setStyleSheet("background-color: #f38ba8; color: #1e1e2e;")
            self.status_label.setText("Starting server...")

    def _stop_client(self):
        """Internal: stop the first client without toggling the UI button state."""
        if self._client_thread:
            self._client_thread.request_stop()
            self._client_thread.wait(3000)
            self._client_thread = None
        self._client_running = False
        self.btn_task.setEnabled(False)
        self.btn_client.setText("Start Client")
        self.btn_client.setStyleSheet("background-color: #a6e3a1; color: #1e1e2e;")

    def _stop_client2(self):
        """Internal: stop the second client without toggling the UI button state."""
        if self._client2_thread:
            self._client2_thread.request_stop()
            self._client2_thread.wait(3000)
            self._client2_thread = None
        self._client2_running = False
        self.btn_task2.setEnabled(False)
        self.btn_client2.setText("Start Client 2")
        self.btn_client2.setStyleSheet("background-color: #cba6f7; color: #1e1e2e;")

    def _toggle_client(self):
        if self._client_running:
            self._stop_client()
            self.btn_client.setText("Start Client")
            self.btn_client.setStyleSheet("background-color: #a6e3a1; color: #1e1e2e;")
            self.status_label.setText("Client disconnected")
        else:
            self._client_thread = ClientThread(self.monitor)
            self._client_thread.connected.connect(self._on_client_connected)
            self._client_thread.error_occurred.connect(
                lambda err: self.status_label.setText(f"Client error: {err}")
            )
            self._client_thread.task_response.connect(self._on_task_response)
            self._client_thread.start()
            self._client_running = True
            self.btn_client.setText("Stop Client")
            self.btn_client.setStyleSheet("background-color: #f38ba8; color: #1e1e2e;")
            self.status_label.setText("Connecting client...")

    def _on_client_connected(self):
        self.status_label.setText("Client connected and bound")
        self.btn_task.setEnabled(True)
        self.monitor.add_event(CONNECTION_OPEN, {
            "conn_id": "client-main",
            "agent": "atp-client",
            "state": "BOUND",
        })

    def _toggle_client2(self):
        if self._client2_running:
            self._stop_client2()
            self.btn_client2.setText("Start Client 2")
            self.btn_client2.setStyleSheet("background-color: #cba6f7; color: #1e1e2e;")
            self.status_label.setText("Client 2 disconnected")
        else:
            self._client2_thread = ClientThread2(self.monitor)
            self._client2_thread.connected.connect(self._on_client2_connected)
            self._client2_thread.error_occurred.connect(
                lambda err: self.status_label.setText(f"Client 2 error: {err}")
            )
            self._client2_thread.task_response.connect(self._on_task_response2)
            self._client2_thread.start()
            self._client2_running = True
            self.btn_client2.setText("Stop Client 2")
            self.btn_client2.setStyleSheet("background-color: #f38ba8; color: #1e1e2e;")
            self.status_label.setText("Connecting client 2...")

    def _on_client2_connected(self):
        self.status_label.setText("Client 2 connected and bound")
        self.btn_task2.setEnabled(True)
        self.monitor.add_event(CONNECTION_OPEN, {
            "conn_id": "client2-main",
            "agent": "atp-client-2",
            "state": "BOUND",
        })

    def _send_test_task(self):
        if not self._client_thread or not self._client_running:
            return
        prompt = self.task_input.text().strip()
        if not prompt:
            prompt = "Spiega il concetto di agenti autonomi basati su LLM a una platea di accademici. Sii preciso e tecnico."
        self.status_label.setText(f"Sending task...")
        self._client_thread.send_task("deepseek_chat", prompt)

    def _send_test_task2(self):
        if not self._client2_thread or not self._client2_running:
            return
        prompt = "Ciao dal secondo agente ATP! Spiega brevemente il concetto di fiducia in sistemi multi-agente."
        self.status_label.setText("Sending task from Client 2...")
        self._client2_thread.send_task("deepseek_chat", prompt)

    def _on_task_response(self, resp: dict):
        ft = resp.get("header", {}).get("frame_type")
        if ft == 0x02:  # TASK_RESPONSE
            payload = resp.get("result_payload", b"")
            try:
                result_text = payload.decode("utf-8")
                preview = result_text[:200]
            except Exception:
                preview = repr(payload[:200])
            self.status_label.setText("Task completed")
            self.event_log.append(f"[Task Response] {preview}")
        elif ft == 0x04:  # TASK_ERROR
            err_msg = resp.get("error_message", "Unknown")
            self.status_label.setText(f"Task error: {err_msg}")

    def _on_task_response2(self, resp: dict):
        ft = resp.get("header", {}).get("frame_type")
        if ft == 0x02:
            payload = resp.get("result_payload", b"")
            try:
                result_text = payload.decode("utf-8")
                preview = result_text[:200]
            except Exception:
                preview = repr(payload[:200])
            self.status_label.setText("Client 2 task completed")
            self.event_log.append(f"[Client 2 Response] {preview}")
        elif ft == 0x04:
            err_msg = resp.get("error_message", "Unknown")
            self.status_label.setText(f"Client 2 task error: {err_msg}")

    def _clear_logs(self):
        self.event_log.clear()
        self.traffic_table.setRowCount(0)
        self.status_label.setText("Logs cleared")

    def _reset_layout(self):
        """Reset the window layout to default size."""
        self.resize(1200, 800)
        self.status_label.setText("Layout reset to 1200x800")

    def _show_about(self):
        QMessageBox.about(
            self,
            "About ATP v1.6.1",
            "Agent Transport Protocol v1.6.1\n"
            "Demo implementation with PySide6 dashboard.\n\n"
            "Built with: blake3, cbor2, cryptography, aiohttp, PySide6, matplotlib\n\n"
            "© 2026 — ATP Project"
        )

    # ── Cleanup ──────────────────────────────────────────────────────────

    def closeEvent(self, event):
        if self._server_thread and self._server_running:
            self._server_thread.request_stop()
            self._server_thread.wait(3000)
        if self._client_thread and self._client_running:
            self._client_thread.request_stop()
            self._client_thread.wait(3000)
        if self._client2_thread and self._client2_running:
            self._client2_thread.request_stop()
            self._client2_thread.wait(3000)
        event.accept()
