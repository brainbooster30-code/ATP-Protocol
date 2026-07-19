"""
ATP v1.7 — Application entry point.
Launches the PySide6 dashboard with the ATP backend.
"""

from __future__ import annotations

import sys
import os
import logging

# Ensure project root is on sys.path
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from PySide6.QtWidgets import QApplication
from monitor import Monitor, MonitorSignals
from dashboard import MainWindow


def setup_logging():
    """Configure logging to file and console."""
    log_dir = os.path.join(_project_root, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "atp.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file, mode="a", encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    logging.getLogger("asyncio").setLevel(logging.ERROR)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
    logging.getLogger("cbor2").setLevel(logging.WARNING)

    return logging.getLogger(__name__)


def main():
    logger = setup_logging()
    logger.info("=" * 60)
    logger.info("ATP v1.7 Dashboard starting...")
    logger.info("=" * 60)

    app = QApplication(sys.argv)
    app.setApplicationName("ATP v1.7 Dashboard")
    app.setOrganizationName("ATP Project")

    # Global monitor (shared across all components)
    monitor = Monitor(max_events=1000)

    window = MainWindow(monitor)
    window.show()

    logger.info("Dashboard window displayed")

    exit_code = app.exec()

    logger.info("ATP Dashboard shutting down (exit code %d)", exit_code)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
