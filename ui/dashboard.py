from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Group
from rich.text import Text

from core.state import stats


class Dashboard:

    def generate_layout(self):

        layout = Layout()

        layout.split_column(
            Layout(name="top", size=12),
            Layout(name="bottom")
        )

        stats_table = Table(title="WireQuokka IDS")

        stats_table.add_column("Metric")
        stats_table.add_column("Value")

        stats_table.add_row("Packets", str(stats["packets"]))
        stats_table.add_row("Suspicious", str(stats["suspicious"]))
        stats_table.add_row("Credentials", str(stats["credentials"]))
        stats_table.add_row("ARP Alerts", str(stats["arp_alerts"]))
        stats_table.add_row("DNS Requests", str(stats["dns_requests"]))
        stats_table.add_row("Active Devices", str(len(stats["devices"])))

        alerts = stats["alerts"][-10:]

        if not alerts:
            alerts_render = Text("No alerts yet")
        else:
            alerts_render = Group(*[Text(a) for a in alerts])

        layout["top"].update(Panel(stats_table))
        layout["bottom"].update(
            Panel(alerts_render, title="Realtime Alerts")
        )

        return layout


dashboard = Dashboard()