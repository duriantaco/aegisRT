
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from jinja2 import Template
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegisrt.core.benchmark import BenchmarkReport


class BenchmarkTerminalReporter:

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def report(self, report: BenchmarkReport) -> None:
        self._print_header(report)
        self._print_matrix(report)
        self._print_ranking(report)

    def _print_header(self, report: BenchmarkReport) -> None:
        self._console.print(
            Panel(
                f"Benchmark ID : {report.benchmark_id}\n"
                f"Timestamp    : {report.timestamp}\n"
                f"Targets      : {len(report.target_names)}\n"
                f"Categories   : {len(report.categories)}",
                title="AegisRT Benchmark",
                border_style="blue",
            )
        )

    def _print_matrix(self, report: BenchmarkReport) -> None:
        matrix = report.summary.get("matrix", {})
        if not matrix:
            return

        table = Table(
            title="Robustness Matrix",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Category", style="bold")
        for name in report.target_names:
            table.add_column(name[:30], justify="center")

        for cat in report.categories:
            row: list[str] = [cat]
            for name in report.target_names:
                rate = matrix.get(cat, {}).get(name, -1.0)
                if rate < 0:
                    row.append("[dim]--[/dim]")
                else:
                    pct = rate * 100
                    if pct >= 95:
                        indicator = "[bold green]✓[/bold green]"
                    elif pct >= 80:
                        indicator = "[yellow]△[/yellow]"
                    else:
                        indicator = "[red]✗[/red]"
                    row.append(f"{pct:.1f}% {indicator}")
            table.add_row(*row)

        overall_row: list[str] = ["[bold]Overall[/bold]"]
        for score in report.scores:
            pct = score.pass_rate * 100
            overall_row.append(f"[bold]{pct:.1f}%[/bold]")
        table.add_row(*overall_row, end_section=True)

        self._console.print(table)

    def _print_ranking(self, report: BenchmarkReport) -> None:
        ranking = report.summary.get("ranking", [])
        if not ranking:
            return

        table = Table(
            title="Ranking",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Rank", justify="center")
        table.add_column("Target", style="bold")
        table.add_column("Pass Rate", justify="right")

        for entry in ranking:
            rank = entry["rank"]
            medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(rank, str(rank))
            pct = entry["pass_rate"] * 100
            if pct >= 95:
                color = "green"
            elif pct >= 80:
                color = "yellow"
            else:
                color = "red"
            table.add_row(
                str(medal),
                entry["target"],
                f"[{color}]{pct:.1f}%[/{color}]",
            )

        self._console.print(table)

        best = report.summary.get("best_target", "")
        best_rate = report.summary.get("best_pass_rate", 0.0)
        if best:
            self._console.print(
                f"\n  [bold green]Most robust:[/bold green] {best} "
                f"({best_rate * 100:.1f}% pass rate)"
            )


_BENCHMARK_HTML = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisRT Benchmark &mdash; {{ benchmark_id }}</title>
<style>
  :root{--bg:
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}
  .container{max-width:1200px;margin:0 auto}
  header{background:linear-gradient(135deg,
  header h1{font-size:1.5rem;margin-bottom:.5rem}
  header .meta{font-size:.9rem;opacity:.85}
  .chart-container{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:2rem;margin-bottom:2rem;text-align:center}
  canvas{max-width:500px;max-height:500px;margin:0 auto}
  table{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;overflow:hidden;margin-bottom:2rem;border:1px solid var(--border)}
  th{background:
  td{padding:.75rem 1rem;border-bottom:1px solid var(--border);font-size:.9rem}
  tr:last-child td{border-bottom:none}
  .rate{font-weight:700}.rate.good{color:var(--pass)}.rate.mid{color:
  .ranking{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
  .rank-card{flex:1;min-width:200px;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;text-align:center}
  .rank-card .medal{font-size:2rem}
  .rank-card .name{font-size:1rem;font-weight:700;margin:.5rem 0}
  .rank-card .pct{font-size:1.5rem;font-weight:700}
  footer{text-align:center;color:
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>AegisRT Benchmark Report</h1>
    <div class="meta">
      Benchmark ID: {{ benchmark_id }} &bull; {{ timestamp }}
      &bull; {{ target_count }} targets &bull; {{ category_count }} categories
    </div>
  </header>

  <div class="ranking">
    {% for entry in ranking %}
    <div class="rank-card">
      <div class="medal">{{ ["🥇","🥈","🥉"][loop.index0] if loop.index0 < 3 else "#" ~ entry.rank }}</div>
      <div class="name">{{ entry.target }}</div>
      <div class="pct {% if entry.pass_rate >= 0.95 %}good{% elif entry.pass_rate >= 0.80 %}mid{% else %}bad{% endif %}">
        {{ "%.1f"|format(entry.pass_rate * 100) }}%
      </div>
    </div>
    {% endfor %}
  </div>

  <div class="chart-container">
    <h2 style="margin-bottom:1rem">Robustness Radar</h2>
    <canvas id="radarChart" width="500" height="500"></canvas>
  </div>

  <table>
    <thead>
      <tr>
        <th>Category</th>
        {% for name in target_names %}<th>{{ name }}</th>{% endfor %}
      </tr>
    </thead>
    <tbody>
    {% for cat in categories %}
      <tr>
        <td><strong>{{ cat }}</strong></td>
        {% for name in target_names %}
        {% set rate = matrix.get(cat, {}).get(name, -1) %}
        {% if rate < 0 %}
        <td style="color:#999">--</td>
        {% else %}
        <td class="rate {% if rate >= 0.95 %}good{% elif rate >= 0.80 %}mid{% else %}bad{% endif %}">
          {{ "%.1f"|format(rate * 100) }}%
        </td>
        {% endif %}
        {% endfor %}
      </tr>
    {% endfor %}
      <tr style="font-weight:700;background:#f1f3f5">
        <td>Overall</td>
        {% for score in scores %}
        <td class="rate {% if score.pass_rate >= 0.95 %}good{% elif score.pass_rate >= 0.80 %}mid{% else %}bad{% endif %}">
          {{ "%.1f"|format(score.pass_rate * 100) }}%
        </td>
        {% endfor %}
      </tr>
    </tbody>
  </table>

  <footer>Generated by AegisRT</footer>
</div>

<script>
// Minimal radar chart — no external deps
(function() {
  const canvas = document.getElementById('radarChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W/2, cy = H/2, R = Math.min(W,H)/2 - 40;

  const categories = {{ categories_json }};
  const datasets = {{ datasets_json }};
  const colors = ['#3498db','#e74c3c','#2ecc71','#f39c12','#9b59b6','#1abc9c','#e67e22','#34495e'];
  const N = categories.length;
  if (N < 3) return;

  function angleFor(i) { return (Math.PI * 2 * i / N) - Math.PI/2; }
  function toXY(i, val) {
    const a = angleFor(i);
    return [cx + R * val * Math.cos(a), cy + R * val * Math.sin(a)];
  }

  // Grid
  ctx.strokeStyle = '#dee2e6'; ctx.lineWidth = 1;
  for (let level = 0.2; level <= 1.0; level += 0.2) {
    ctx.beginPath();
    for (let i = 0; i <= N; i++) {
      const [x,y] = toXY(i % N, level);
      if (i === 0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
    }
    ctx.stroke();
  }
  // Axes
  for (let i = 0; i < N; i++) {
    const [x,y] = toXY(i, 1.0);
    ctx.beginPath(); ctx.moveTo(cx,cy); ctx.lineTo(x,y); ctx.stroke();
    // Label
    const [lx,ly] = toXY(i, 1.15);
    ctx.fillStyle = '#212529'; ctx.font = '12px sans-serif'; ctx.textAlign = 'center';
    ctx.fillText(categories[i], lx, ly + 4);
  }

  // Datasets
  datasets.forEach(function(ds, di) {
    const color = colors[di % colors.length];
    ctx.beginPath();
    ds.values.forEach(function(v, i) {
      const [x,y] = toXY(i, v);
      if (i === 0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
    });
    ctx.closePath();
    ctx.fillStyle = color + '33';
    ctx.fill();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();
    // Points
    ds.values.forEach(function(v, i) {
      const [x,y] = toXY(i, v);
      ctx.beginPath(); ctx.arc(x,y,4,0,Math.PI*2); ctx.fillStyle = color; ctx.fill();
    });
  });

  // Legend
  let ly = 15;
  datasets.forEach(function(ds, di) {
    ctx.fillStyle = colors[di % colors.length];
    ctx.fillRect(10, ly-10, 12, 12);
    ctx.fillStyle = '#212529'; ctx.font = '12px sans-serif'; ctx.textAlign = 'left';
    ctx.fillText(ds.name, 26, ly);
    ly += 18;
  });
})();
</script>
</body>
</html>
""")


class BenchmarkHtmlReportWriter:

    def write(self, report: BenchmarkReport, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        matrix = report.summary.get("matrix", {})
        ranking = report.summary.get("ranking", [])

        datasets: list[dict[str, Any]] = []
        for score in report.scores:
            values: list[float] = []
            for cat in report.categories:
                cat_stats = score.by_category.get(cat)
                values.append(cat_stats["pass_rate"] if cat_stats else 0.0)
            datasets.append({"name": score.target_name, "values": values})

        html = _BENCHMARK_HTML.render(
            benchmark_id=report.benchmark_id,
            timestamp=report.timestamp,
            target_count=len(report.target_names),
            category_count=len(report.categories),
            target_names=report.target_names,
            categories=report.categories,
            matrix=matrix,
            scores=report.scores,
            ranking=ranking,
            categories_json=json.dumps(report.categories),
            datasets_json=json.dumps(datasets),
        )
        out.write_text(html, encoding="utf-8")
        return out.resolve()


class BenchmarkCsvReportWriter:

    def write(self, report: BenchmarkReport, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = ["category"] + report.target_names

        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            matrix = report.summary.get("matrix", {})
            for cat in report.categories:
                row: dict[str, str] = {"category": cat}
                for name in report.target_names:
                    rate = matrix.get(cat, {}).get(name, -1.0)
                    row[name] = f"{rate * 100:.1f}%" if rate >= 0 else "N/A"
                writer.writerow(row)

            overall: dict[str, str] = {"category": "OVERALL"}
            for score in report.scores:
                overall[score.target_name] = f"{score.pass_rate * 100:.1f}%"
            writer.writerow(overall)

        return out.resolve()
