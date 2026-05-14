from core.sniffer import start_sniffer
from ui.dashboard import dashboard
from rich.live import Live
import threading


def run_dashboard():
    with Live(dashboard.generate_layout(), refresh_per_second=2) as live:
        while True:
            live.update(dashboard.generate_layout())


if __name__ == "__main__":
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()

    start_sniffer()