#!/usr/bin/env python3
"""Build an HTML report from bench/scripts/extract_results.sh output.

Usage:
    bench/scripts/report.py [RESULTS.tsv ...] [--out FILE]

With no RESULTS.tsv given, uses every bench/out/results.*.tsv. Writes a
single self-contained HTML fragment (no <html>/<head>/<body> -- safe to
open directly in a browser, or to publish as-is) to --out (default:
bench/out/report.<timestamp>.html).

Two sections:
  1. Every cxi result (UCT and UCP), full metric detail.
  2. TCP vs cxi for UCP tests only -- the protocol layer is what actually
     has to route requests onto one transport or the other, so comparing
     there captures whatever overhead UCP itself adds, not just the raw
     wire difference. UCT-level tests aren't compared here since most of
     them don't run over tcp at all (see sweep_perftest.sh).

Rows are deduplicated by (test, type, transport, device, layout); when two
rows for the same key disagree, the later one (by input file order) wins
and a warning is printed to stderr.
"""
import csv
import glob
import math
import sys
from datetime import datetime, timezone

NUMERIC_FIELDS = [
    "iterations", "pctile_rank", "latency_pctile_usec", "latency_avg_usec",
    "latency_overall_usec", "bw_avg_MBps", "bw_overall_MBps",
    "msgrate_avg_pps", "msgrate_overall_pps",
]


def load_rows(paths):
    by_key = {}
    order = []
    for path in paths:
        with open(path, newline="") as f:
            for row in csv.DictReader(f, delimiter="\t"):
                key = (row["test"], row["type"], row["transport"],
                       row["device"], row["layout"])
                if row["status"] == "ok":
                    for field in NUMERIC_FIELDS:
                        row[field] = float(row[field])
                if key in by_key and by_key[key] != row:
                    print(f"warning: conflicting duplicate rows for {key}, "
                          f"keeping the later one ({path})", file=sys.stderr)
                if key not in by_key:
                    order.append(key)
                by_key[key] = row
    return [by_key[k] for k in order]


def fmt(value, digits=3):
    if value is None or value == "":
        return "—"
    if isinstance(value, float):
        if value >= 1000:
            return f"{value:,.0f}"
        return f"{value:.{digits}f}"
    return str(value)


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


_LATEX_SPECIAL = {
    "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$",
    "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}",
    "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
}


def latex_escape(s):
    return "".join(_LATEX_SPECIAL.get(ch, ch) for ch in str(s))


def latex_fmt(value, digits=3):
    # "--" not the em dash fmt() uses: safe in plain pdflatex with no
    # inputenc/fontenc assumptions about the reader's document class.
    if value is None or value == "":
        return "--"
    if isinstance(value, float):
        if value >= 1000:
            return f"{value:,.0f}"
        return f"{value:.{digits}f}"
    return str(value)


TEST_ORDER = [
    # UCT
    "am_lat", "put_lat", "add_lat", "get", "fadd", "swap", "cswap",
    "am_bw", "put_bw", "get_bw", "add_mr",
    # UCP
    "tag_lat", "tag_bw", "tag_sync_lat", "tag_sync_bw",
    "ucp_put_lat", "ucp_put_bw", "ucp_get", "ucp_add", "ucp_fadd",
    "ucp_swap", "ucp_cswap", "stream_bw", "stream_lat",
    "ucp_am_lat", "ucp_am_bw",
]


def test_sort_key(test):
    try:
        return (0, TEST_ORDER.index(test))
    except ValueError:
        return (1, test)


TYPE_ORDER = {"UCT": 0, "UCP": 1}  # transport layer before protocol layer


def build_cxi_table(rows):
    cxi = [r for r in rows if r["transport"] == "cxi"]
    cxi.sort(key=lambda r: (TYPE_ORDER.get(r["type"], 2), test_sort_key(r["test"])))
    return cxi


def build_latex_table(cxi_table):
    # Only completed runs: a publication table shouldn't carry "--" rows
    # for tests that errored out or hit the sweep timeout.
    rows = [r for r in cxi_table if r["status"] == "ok"]
    skipped = len(cxi_table) - len(rows)

    lines = [
        r"\begin{table}",
        r"  \centering",
        r"  \caption{\texttt{ucx\_perftest} results on cxi/cxi0 "
        r"(2 nodes, 1 task/node, short layout). "
        r"Latency in $\mu$s, bandwidth in MB/s, message rate in Kmsg/s.}",
        r"  \label{tab:cxi-results}",
        r"  \begin{tabular}{lrrrrrrr}",
        r"    \toprule",
        r"    Test & Iters & Lat avg & Lat ovr & BW avg & BW ovr & "
        r"MR avg & MR ovr \\",
        r"    \midrule",
    ]

    last_type = None
    for r in rows:
        if r["type"] != last_type:
            if last_type is not None:
                lines.append(r"    \midrule")
            label = ("UCT (transport layer)" if r["type"] == "UCT"
                      else "UCP (protocol layer)")
            lines.append(rf"    \multicolumn{{8}}{{l}}{{\textit{{{label}}}}} \\")
            lines.append(r"    \midrule")
            last_type = r["type"]
        lines.append(
            f'    {latex_escape(r["test"])} & '
            f'{latex_fmt(r["iterations"], 0)} & '
            f'{latex_fmt(r["latency_avg_usec"])} & '
            f'{latex_fmt(r["latency_overall_usec"])} & '
            f'{latex_fmt(r["bw_avg_MBps"], 2)} & '
            f'{latex_fmt(r["bw_overall_MBps"], 2)} & '
            f'{latex_fmt(r["msgrate_avg_pps"] / 1000, 1)} & '
            f'{latex_fmt(r["msgrate_overall_pps"] / 1000, 1)} \\\\'
        )

    lines += [r"    \bottomrule", r"  \end{tabular}", r"\end{table}"]
    return "\n".join(lines), skipped


def build_ucp_comparison(rows):
    by_key = {(r["test"], r["transport"]): r for r in rows if r["type"] == "UCP"}
    ucp_tests = sorted({r["test"] for r in rows if r["type"] == "UCP"},
                        key=test_sort_key)
    compared, excluded = [], []
    for t in ucp_tests:
        c = by_key.get((t, "cxi"))
        p = by_key.get((t, "tcp"))
        c_ok = c is not None and c["status"] == "ok"
        p_ok = p is not None and p["status"] == "ok"
        if c_ok and p_ok:
            compared.append({
                "test": t,
                "cxi_lat": c["latency_avg_usec"], "tcp_lat": p["latency_avg_usec"],
                "cxi_bw": c["bw_avg_MBps"], "tcp_bw": p["bw_avg_MBps"],
                "cxi_mr": c["msgrate_avg_pps"], "tcp_mr": p["msgrate_avg_pps"],
                "lat_ratio": p["latency_avg_usec"] / c["latency_avg_usec"],
                "bw_ratio": c["bw_avg_MBps"] / p["bw_avg_MBps"],
                "mr_ratio": c["msgrate_avg_pps"] / p["msgrate_avg_pps"],
            })
        else:
            excluded.append({
                "test": t,
                "cxi_status": c["status"] if c else "not run",
                "tcp_status": p["status"] if p else "not run",
            })
    compared.sort(key=lambda r: -r["lat_ratio"])
    return compared, excluded


def build_latex_comparison_table(compared, excluded):
    # Same column headers as the HTML report's UCP comparison table
    # (render()), not abbreviated further -- verbose on purpose.
    #
    # 10 columns confirmed too wide for a stock article-class page (252pt
    # overflow, columns silently cut off, not just an Overfull warning) --
    # wrapped in \resizebox{\textwidth}{!}{...} (requires graphicx), which
    # was verified to bring it to 0 Overfull warnings and fit the page.
    lines = [
        r"\begin{table}",
        r"  \centering",
        r"  \caption{TCP vs cxi, UCP layer, averages (2 nodes, 1 task/node, "
        r"short layout). $\times$ columns are cxi's factor of improvement "
        r"over tcp.}",
        r"  \label{tab:ucp-comparison}",
        r"  \resizebox{\textwidth}{!}{%",
        r"  \begin{tabular}{lrrrrrrrrr}",
        r"    \toprule",
        r"    Test & cxi lat ($\mu$s) & tcp lat ($\mu$s) & lat $\times$ & "
        r"cxi bw (MB/s) & tcp bw (MB/s) & bw $\times$ & "
        r"cxi mr (K/s) & tcp mr (K/s) & mr $\times$ \\",
        r"    \midrule",
    ]

    for r in compared:
        lines.append(
            f'    {latex_escape(r["test"])} & '
            f'{latex_fmt(r["cxi_lat"])} & {latex_fmt(r["tcp_lat"])} & '
            f'{r["lat_ratio"]:.1f}$\\times$ & '
            f'{latex_fmt(r["cxi_bw"], 2)} & {latex_fmt(r["tcp_bw"], 2)} & '
            f'{r["bw_ratio"]:.1f}$\\times$ & '
            f'{latex_fmt(r["cxi_mr"] / 1000, 1)} & '
            f'{latex_fmt(r["tcp_mr"] / 1000, 1)} & '
            f'{r["mr_ratio"]:.1f}$\\times$ \\\\'
        )

    lines += [r"    \bottomrule", r"  \end{tabular}%", r"  }", r"\end{table}"]

    if excluded:
        lines.append("% Not compared (missing a successful run on one side):")
        for e in excluded:
            lines.append(f'%   {e["test"]}: cxi={e["cxi_status"]}, '
                          f'tcp={e["tcp_status"]}')

    return "\n".join(lines)


def geomean(values):
    return math.exp(sum(math.log(v) for v in values) / len(values))


# ---------------------------------------------------------------------------
# SVG: log-scale horizontal grouped bar chart (cxi vs tcp latency)
# ---------------------------------------------------------------------------

# Fixed light-mode hex values, for the standalone chart export: it has no
# access to the report page's external <style> block or CSS custom
# properties, and is meant to be pasted as-is (e.g. into a doc), so it
# can't follow the viewer's OS theme -- it commits to one, always-white,
# background instead.
STANDALONE_COLORS = {
    "border": "#d7dce3", "muted": "#7c8194", "secondary": "#52586b",
    "primary": "#14171c", "cxi": "#eb6834", "tcp": "#2a78d6",
}


def latency_chart_svg(compared, standalone=False):
    if not compared:
        return ""

    all_vals = [r["cxi_lat"] for r in compared] + [r["tcp_lat"] for r in compared]
    lo = min(all_vals) / 1.6
    hi = max(all_vals) * 1.6
    log_lo, log_hi = math.log10(lo), math.log10(hi)

    row_h = 44
    bar_h = 14
    gap_within = 3
    top_pad, bottom_pad = 12, 34
    left_pad, right_pad = 132, 76
    plot_w = 560
    n = len(compared)
    plot_h = n * row_h
    legend_h = 28 if standalone else 0
    width = left_pad + plot_w + right_pad
    height = legend_h + top_pad + plot_h + bottom_pad
    top_pad += legend_h

    def x(v):
        return left_pad + (math.log10(v) - log_lo) / (log_hi - log_lo) * plot_w

    ticks = [t for t in [0.5, 1, 2, 5, 10, 20, 50, 100] if lo <= t <= hi]

    parts = [
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'class="chart-latency" role="img" '
        f'aria-label="Average latency, cxi versus tcp, per UCP test">'
    ]

    if standalone:
        c = STANDALONE_COLORS
        parts.append(f'''<style>
            text {{ font-family: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, monospace; }}
            .grid-line {{ stroke: {c["border"]}; stroke-width: 1; }}
            .axis-label {{ fill: {c["muted"]}; font-size: 10px; }}
            .axis-title {{ fill: {c["secondary"]}; font-size: 11px; }}
            .row-label {{ fill: {c["primary"]}; font-size: 12px; font-family: ui-sans-serif, sans-serif; }}
            .val-label {{ fill: {c["secondary"]}; font-size: 10px; }}
            .ratio-label {{ fill: {c["cxi"]}; font-size: 12px; font-weight: 600; }}
            .bar-cxi {{ fill: {c["cxi"]}; }}
            .bar-tcp {{ fill: {c["tcp"]}; }}
            .legend-label {{ fill: {c["secondary"]}; font-size: 12px; font-family: ui-sans-serif, sans-serif; }}
        </style>''')
        parts.append(f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff" />')
        parts.append(
            f'<rect x="{left_pad}" y="10" width="10" height="10" rx="2" class="bar-cxi" />'
            f'<text x="{left_pad + 16}" y="19" class="legend-label">cxi</text>'
            f'<rect x="{left_pad + 60}" y="10" width="10" height="10" rx="2" class="bar-tcp" />'
            f'<text x="{left_pad + 76}" y="19" class="legend-label">tcp</text>'
        )

    # gridlines + tick labels
    for t in ticks:
        gx = x(t)
        parts.append(f'<line x1="{gx:.1f}" y1="{top_pad}" x2="{gx:.1f}" '
                      f'y2="{top_pad + plot_h}" class="grid-line" />')
        label = f"{t:g}"
        parts.append(f'<text x="{gx:.1f}" y="{top_pad + plot_h + 20}" '
                      f'class="axis-label" text-anchor="middle">{label}</text>')
    parts.append(f'<text x="{left_pad + plot_w / 2:.1f}" y="{height - 4}" '
                  f'class="axis-title" text-anchor="middle">'
                  f'average latency, μs (log scale) — shorter is faster</text>')

    for i, r in enumerate(compared):
        cy = top_pad + i * row_h
        mid = cy + row_h / 2
        cxi_y = mid - gap_within / 2 - bar_h
        tcp_y = mid + gap_within / 2

        parts.append(f'<text x="{left_pad - 12}" y="{mid + 4:.1f}" '
                      f'class="row-label" text-anchor="end">{esc(r["test"])}</text>')

        cxi_x = x(r["cxi_lat"])
        tcp_x = x(r["tcp_lat"])
        parts.append(
            f'<g class="bar-group">'
            f'<title>{esc(r["test"])} cxi: {r["cxi_lat"]:.3f} μs, '
            f'tcp: {r["tcp_lat"]:.3f} μs ({r["lat_ratio"]:.1f}× faster on cxi)</title>'
            f'<rect x="{left_pad}" y="{cxi_y:.1f}" width="{cxi_x - left_pad:.1f}" '
            f'height="{bar_h}" rx="3" class="bar-cxi" />'
            f'<rect x="{left_pad}" y="{tcp_y:.1f}" width="{tcp_x - left_pad:.1f}" '
            f'height="{bar_h}" rx="3" class="bar-tcp" />'
            f'<text x="{cxi_x + 6:.1f}" y="{cxi_y + bar_h - 3:.1f}" class="val-label">'
            f'{r["cxi_lat"]:.2f}</text>'
            f'<text x="{tcp_x + 6:.1f}" y="{tcp_y + bar_h - 3:.1f}" class="val-label">'
            f'{r["tcp_lat"]:.2f}</text>'
            f'<text x="{width - right_pad + 14}" y="{mid + 4:.1f}" class="ratio-label">'
            f'{r["lat_ratio"]:.1f}×</text>'
            f'</g>'
        )

    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

STYLE = """
<style>
.perf-report {
  --surface-1: #f6f7f9;
  --surface-2: #ffffff;
  --surface-3: #ebeef2;
  --border: #d7dce3;
  --text-primary: #14171c;
  --text-secondary: #52586b;
  --text-muted: #7c8194;
  --cxi: #eb6834;
  --cxi-soft: #f7cbb3;
  --tcp: #2a78d6;
  --tcp-soft: #b9d3f2;
  --good: #1f8a4c;
  --warn: #b8860b;
  --bad: #c0392b;
  color-scheme: light;
  background: var(--surface-1);
  color: var(--text-primary);
  font-family: ui-sans-serif, "Segoe UI", Helvetica, Arial, sans-serif;
  line-height: 1.5;
  max-width: 980px;
  margin: 0 auto;
  padding: 40px 24px 80px;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) .perf-report {
    --surface-1: #14171c;
    --surface-2: #1b1f26;
    --surface-3: #232833;
    --border: #333a47;
    --text-primary: #f2f3f5;
    --text-secondary: #a7adbe;
    --text-muted: #7c8194;
    --cxi: #d95926;
    --cxi-soft: #5a3420;
    --tcp: #3987e5;
    --tcp-soft: #203a5a;
    --good: #3dbd72;
    --warn: #d9a521;
    --bad: #e0574a;
    color-scheme: dark;
  }
}
:root[data-theme="dark"] .perf-report {
  --surface-1: #14171c;
  --surface-2: #1b1f26;
  --surface-3: #232833;
  --border: #333a47;
  --text-primary: #f2f3f5;
  --text-secondary: #a7adbe;
  --text-muted: #7c8194;
  --cxi: #d95926;
  --cxi-soft: #5a3420;
  --tcp: #3987e5;
  --tcp-soft: #203a5a;
  --good: #3dbd72;
  --warn: #d9a521;
  --bad: #e0574a;
  color-scheme: dark;
}
:root[data-theme="light"] .perf-report {
  --surface-1: #f6f7f9;
  --surface-2: #ffffff;
  --surface-3: #ebeef2;
  --border: #d7dce3;
  --text-primary: #14171c;
  --text-secondary: #52586b;
  --text-muted: #7c8194;
  --cxi: #eb6834;
  --cxi-soft: #f7cbb3;
  --tcp: #2a78d6;
  --tcp-soft: #b9d3f2;
  --good: #1f8a4c;
  --warn: #b8860b;
  --bad: #c0392b;
  color-scheme: light;
}
.perf-report * { box-sizing: border-box; }
.perf-report h1, .perf-report h2, .perf-report h3 {
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
  font-weight: 600;
  text-wrap: balance;
  color: var(--text-primary);
}
.perf-report h1 { font-size: 30px; margin: 0 0 6px; letter-spacing: -0.01em; }
.perf-report h2 { font-size: 20px; margin: 0 0 4px; }
.perf-report h3 { font-size: 15px; margin: 0; }
.perf-report .subtitle { color: var(--text-secondary); font-size: 15px; margin: 0 0 4px; }
.perf-report .meta {
  color: var(--text-muted); font-size: 12.5px; margin: 0 0 32px;
  font-family: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, monospace;
}
.perf-report header { border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 28px; }
.perf-report section { margin-bottom: 48px; }
.perf-report .section-head { margin-bottom: 16px; }
.perf-report .section-note { color: var(--text-secondary); font-size: 13.5px; max-width: 68ch; }

.perf-report .stat-row {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1px; background: var(--border); border: 1px solid var(--border);
  border-radius: 8px; overflow: hidden; margin-bottom: 32px;
}
.perf-report .stat-tile { background: var(--surface-2); padding: 14px 16px; }
.perf-report .stat-value {
  font-family: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums; font-size: 24px; font-weight: 600;
  color: var(--cxi);
}
.perf-report .stat-label { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }

.perf-report .table-scroll { overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; }
.perf-report table { border-collapse: collapse; width: 100%; font-size: 13px; background: var(--surface-2); }
.perf-report th, .perf-report td {
  padding: 7px 12px; text-align: right; white-space: nowrap;
  font-family: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
}
.perf-report th:first-child, .perf-report td:first-child {
  text-align: left; font-family: inherit; font-weight: 500;
}
.perf-report thead th {
  background: var(--surface-3); color: var(--text-secondary);
  font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em;
  border-bottom: 1px solid var(--border); position: sticky; top: 0;
}
.perf-report tbody tr + tr { border-top: 1px solid var(--border); }
.perf-report tbody tr.group-start td:first-child { padding-top: 12px; }
.perf-report .cat-badge {
  display: inline-block; font-size: 10px; font-weight: 700; letter-spacing: 0.04em;
  padding: 1px 6px; border-radius: 4px; margin-right: 8px; font-family: ui-sans-serif, sans-serif;
}
.perf-report .cat-uct { background: var(--surface-3); color: var(--text-secondary); }
.perf-report .cat-ucp { background: var(--surface-3); color: var(--text-secondary); }

.perf-report .legend { display: flex; gap: 18px; align-items: center; font-size: 13px; color: var(--text-secondary); margin-bottom: 4px; }
.perf-report .legend-item { display: flex; gap: 6px; align-items: center; }
.perf-report .swatch { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.perf-report .swatch-cxi { background: var(--cxi); }
.perf-report .swatch-tcp { background: var(--tcp); }

.perf-report .chart-wrap { border: 1px solid var(--border); border-radius: 8px; background: var(--surface-2); padding: 16px 8px; overflow-x: auto; }
.perf-report svg.chart-latency { display: block; margin: 0 auto; font-family: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, monospace; }
.perf-report .grid-line { stroke: var(--border); stroke-width: 1; }
.perf-report .axis-label { fill: var(--text-muted); font-size: 10px; }
.perf-report .axis-title { fill: var(--text-secondary); font-size: 11px; }
.perf-report .row-label { fill: var(--text-primary); font-size: 12px; }
.perf-report .val-label { fill: var(--text-secondary); font-size: 10px; }
.perf-report .ratio-label { fill: var(--cxi); font-size: 12px; font-weight: 600; text-anchor: start; dominant-baseline: middle; }
.perf-report .bar-cxi { fill: var(--cxi); }
.perf-report .bar-tcp { fill: var(--tcp); }

.perf-report .status-ok { color: var(--good); }
.perf-report .status-bad { color: var(--bad); }
.perf-report .excluded-list { font-size: 13px; color: var(--text-secondary); }
.perf-report .excluded-list code { font-family: ui-monospace, monospace; }
.perf-report footer { border-top: 1px solid var(--border); padding-top: 16px; color: var(--text-muted); font-size: 12px; }
.perf-report footer p { max-width: 72ch; }
</style>
"""


def render(rows, generated_at, sources):
    cxi_table = build_cxi_table(rows)
    compared, excluded = build_ucp_comparison(rows)

    html = [STYLE, '<div class="perf-report">']

    html.append('<header>')
    html.append('<h1>CXI vs TCP: ucx_perftest sweep</h1>')
    html.append('<p class="subtitle">Preliminary two-node results from '
                 'bench/scripts/sweep_perftest.sh</p>')
    html.append(f'<p class="meta">generated {esc(generated_at)} '
                 f'&middot; source: {esc(", ".join(sources))}</p>')
    html.append('</header>')

    # --- headline stats -----------------------------------------------
    if compared:
        lat_speedups = [r["lat_ratio"] for r in compared]
        best = max(compared, key=lambda r: r["lat_ratio"])
        html.append('<div class="stat-row">')
        html.append(f'<div class="stat-tile"><div class="stat-value">'
                     f'{geomean(lat_speedups):.1f}×</div>'
                     f'<div class="stat-label">avg latency speedup, cxi vs tcp '
                     f'(geomean, {len(compared)} UCP tests)</div></div>')
        html.append(f'<div class="stat-tile"><div class="stat-value">'
                     f'{best["lat_ratio"]:.1f}×</div>'
                     f'<div class="stat-label">largest speedup '
                     f'({esc(best["test"])})</div></div>')
        html.append(f'<div class="stat-tile"><div class="stat-value">'
                     f'{min(lat_speedups):.1f}×</div>'
                     f'<div class="stat-label">smallest speedup</div></div>')
        html.append(f'<div class="stat-tile"><div class="stat-value">'
                     f'{len(cxi_table)}</div>'
                     f'<div class="stat-label">cxi tests completed</div></div>')
        html.append('</div>')

    # --- section 1: full cxi table -------------------------------------
    html.append('<section>')
    html.append('<div class="section-head"><h2>All cxi results</h2>'
                 '<p class="section-note">Every test that completed on cxi/cxi0, '
                 'transport layer (UCT) and protocol layer (UCP).</p></div>')
    html.append('<div class="table-scroll"><table><thead><tr>'
                 '<th>Test</th><th>Iterations</th>'
                 '<th>Latency avg (μs)</th><th>Latency overall (μs)</th>'
                 '<th>Bandwidth avg (MB/s)</th><th>Bandwidth overall (MB/s)</th>'
                 '<th>Msg rate avg (K/s)</th><th>Msg rate overall (K/s)</th>'
                 '</tr></thead><tbody>')
    last_type = None
    for r in cxi_table:
        group_start = r["type"] != last_type
        last_type = r["type"]
        cls = "group-start" if group_start else ""
        badge = (f'<span class="cat-badge cat-{r["type"].lower()}">{r["type"]}</span>'
                  if group_start else '<span style="display:inline-block;width:38px"></span>')
        html.append(
            f'<tr class="{cls}"><td>{badge}{esc(r["test"])}</td>'
            f'<td>{fmt(r["iterations"], 0)}</td>'
            f'<td>{fmt(r["latency_avg_usec"])}</td>'
            f'<td>{fmt(r["latency_overall_usec"])}</td>'
            f'<td>{fmt(r["bw_avg_MBps"], 2)}</td>'
            f'<td>{fmt(r["bw_overall_MBps"], 2)}</td>'
            f'<td>{fmt(r["msgrate_avg_pps"] / 1000, 1)}</td>'
            f'<td>{fmt(r["msgrate_overall_pps"] / 1000, 1)}</td></tr>'
        )
    html.append('</tbody></table></div>')
    html.append('</section>')

    # --- section 2: ucp comparison --------------------------------------
    html.append('<section>')
    html.append('<div class="section-head"><h2>TCP vs cxi &mdash; UCP layer</h2>'
                 '<p class="section-note">Compared at the UCP (protocol) layer, '
                 'not UCT, because that is the layer that actually has to route '
                 'onto one transport or the other &mdash; this captures any '
                 'overhead UCP itself adds on top of the raw transport, not just '
                 'the wire difference. Most UCT-level tests don’t run over '
                 'tcp at all (no atomics, no GET), so a UCT-layer comparison '
                 'would mostly compare errors.</p></div>')

    if compared:
        html.append('<div class="legend">'
                     '<div class="legend-item"><span class="swatch swatch-cxi"></span>cxi</div>'
                     '<div class="legend-item"><span class="swatch swatch-tcp"></span>tcp</div>'
                     '</div>')
        html.append('<div class="chart-wrap">')
        html.append(latency_chart_svg(compared))
        html.append('</div>')

        html.append('<div class="table-scroll" style="margin-top:16px"><table><thead><tr>'
                     '<th>Test</th>'
                     '<th>cxi lat (μs)</th><th>tcp lat (μs)</th><th>lat ×</th>'
                     '<th>cxi bw (MB/s)</th><th>tcp bw (MB/s)</th><th>bw ×</th>'
                     '<th>cxi mr (K/s)</th><th>tcp mr (K/s)</th><th>mr ×</th>'
                     '</tr></thead><tbody>')
        for r in compared:
            html.append(
                f'<tr><td>{esc(r["test"])}</td>'
                f'<td>{fmt(r["cxi_lat"])}</td><td>{fmt(r["tcp_lat"])}</td>'
                f'<td>{r["lat_ratio"]:.1f}×</td>'
                f'<td>{fmt(r["cxi_bw"], 2)}</td><td>{fmt(r["tcp_bw"], 2)}</td>'
                f'<td>{r["bw_ratio"]:.1f}×</td>'
                f'<td>{fmt(r["cxi_mr"]/1000, 1)}</td><td>{fmt(r["tcp_mr"]/1000, 1)}</td>'
                f'<td>{r["mr_ratio"]:.1f}×</td></tr>'
            )
        html.append('</tbody></table></div>')
        html.append('<p class="section-note" style="margin-top:10px">Latency, '
                     'bandwidth, and message-rate ratios track closely for each '
                     'test &mdash; expected at this fixed (short) message size, '
                     'where bandwidth and message rate are essentially the '
                     'reciprocal of latency.</p>')
    else:
        html.append('<p class="section-note">No UCP test has a successful run on '
                     'both cxi and tcp yet.</p>')

    if excluded:
        html.append('<p class="section-note" style="margin-top:18px">'
                     '<strong>Not compared</strong> (missing a successful run on '
                     'one side):</p>')
        html.append('<p class="excluded-list">')
        html.append(", ".join(
            f'<code>{esc(e["test"])}</code> (cxi: {esc(e["cxi_status"])}, '
            f'tcp: {esc(e["tcp_status"])})' for e in excluded
        ))
        html.append('</p>')
    html.append('</section>')

    html.append('<footer><p>Preliminary data from an in-progress sweep &mdash; '
                 'coverage will grow as more tests complete. Generated by '
                 'bench/scripts/report.py from bench/scripts/extract_results.sh '
                 'output.</p></footer>')

    html.append('</div>')
    return "".join(html)


def main(argv):
    args = argv[1:]
    out_path = None
    chart_path = None
    latex_path = None
    latex_comparison_path = None
    inputs = []
    i = 0
    while i < len(args):
        if args[i] == "--out":
            out_path = args[i + 1]
            i += 2
        elif args[i] == "--chart":
            chart_path = args[i + 1]
            i += 2
        elif args[i] == "--latex":
            latex_path = args[i + 1]
            i += 2
        elif args[i] == "--latex-comparison":
            latex_comparison_path = args[i + 1]
            i += 2
        elif args[i] in ("-h", "--help"):
            print(__doc__)
            print("\nAlso:\n"
                  "  --chart FILE.svg  just the UCP latency comparison chart, "
                  "self-contained (inline styles, white background) so it can "
                  "be copied or converted to an image standalone, e.g. with "
                  "rsvg-convert.\n"
                  "  --latex FILE.tex  just the all-cxi-results table as a "
                  "booktabs tabular, ready to \\input{} or paste in.\n"
                  "  --latex-comparison FILE.tex  just the tcp-vs-cxi UCP "
                  "comparison table, same verbose column headers as the HTML "
                  "report, as a booktabs tabular.")
            return 0
        else:
            inputs.append(args[i])
            i += 1

    if not inputs:
        inputs = sorted(glob.glob("bench/out/results.*.tsv"))
    if not inputs:
        print("error: no results TSV given and no bench/out/results.*.tsv found",
              file=sys.stderr)
        return 1

    rows = load_rows(inputs)

    if chart_path is not None:
        compared, _ = build_ucp_comparison(rows)
        if not compared:
            print("error: no UCP test has a successful run on both cxi and tcp",
                  file=sys.stderr)
            return 1
        with open(chart_path, "w") as f:
            f.write(latency_chart_svg(compared, standalone=True))
        print(f"Chart: {chart_path}")
        return 0

    if latex_path is not None:
        cxi_table = build_cxi_table(rows)
        if not cxi_table:
            print("error: no cxi results found", file=sys.stderr)
            return 1
        table, skipped = build_latex_table(cxi_table)
        with open(latex_path, "w") as f:
            f.write(table + "\n")
        print(f"LaTeX table: {latex_path}")
        if skipped:
            print(f"({skipped} non-ok cxi row(s) excluded)", file=sys.stderr)
        return 0

    if latex_comparison_path is not None:
        compared, excluded = build_ucp_comparison(rows)
        if not compared:
            print("error: no UCP test has a successful run on both cxi and tcp",
                  file=sys.stderr)
            return 1
        table = build_latex_comparison_table(compared, excluded)
        with open(latex_comparison_path, "w") as f:
            f.write(table + "\n")
        print(f"LaTeX table: {latex_comparison_path}")
        if excluded:
            print(f"({len(excluded)} UCP test(s) excluded, listed as a "
                  f"comment in the file)", file=sys.stderr)
        return 0

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = render(rows, generated_at, inputs)

    if out_path is None:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = f"bench/out/report.{ts}.html"
    with open(out_path, "w") as f:
        f.write(html)
    print(f"Report: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
