---
tags:
  - dashboard
  - gui
  - pyside6
---

# Dashboard

## Technology
PySide6 (Qt for Python) with dark theme (Catppuccin Mocha).

## Tabs (5)
- **Overview** — 8 metric cards + event log
- **Traffic** — real-time frame event table with filter
- **Connections** — per-connection status table
- **Agents** — agent identity (X25519 PK, Ed25519 PK, MCC hash, status)
- **Tasks** — task history (request, response, latency, status)

## Architecture
- Server and 2 clients run in separate `QThread` with own `asyncio` event loops
- Thread-safe via `pyqtSignal` + `Monitor`
- Matplotlib chart for frame traffic (per-second rates)
- Task serialization via `asyncio.Lock` in `ATPAgent.send_task()`

## Toolbar Buttons
- Start/Stop Server — `reuse_address=True` for fast restart
- Start/Stop Client — connects once, must toggle to reconnect
- Start/Stop Client 2 — second agent with different identity
- Send Task / Send Task 2 — sends deepseek_chat with text prompt
- Clear Logs

## Key Classes
- `ServerThread(QThread)` — `loop.create_task() + loop.run_forever()`
- `ClientThread(QThread)` — connects then `loop.run_forever()`
- `ClientThread2(QThread)` — same as ClientThread with `atp-client-2` identity
- `TrafficChart(FigureCanvas)` — matplotlib live-updating line chart
