import json
from html import escape
from pathlib import Path


def _load_report(json_path: Path) -> dict:
    if not json_path.exists():
        return {"results": [], "metrics": {"_totals": {"loc": 0, "nosec": 0}}}

    with json_path.open(encoding="utf-8-sig") as file_handle:
        return json.load(file_handle)


def _severity_counts(results: list[dict]) -> dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for issue in results:
        severity = issue.get("issue_severity", "LOW")
        if severity in counts:
            counts[severity] += 1
    return counts


def _sort_issues(results: list[dict]) -> list[dict]:
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(results, key=lambda issue: (severity_order.get(issue.get("issue_severity", "LOW"), 3), issue.get("line_number", 0)))


def build_report(json_path: Path, html_path: Path) -> None:
    report = _load_report(json_path)
    results = _sort_issues(report.get("results", []))
    totals = (report.get("metrics", {}) or {}).get("_totals", {}) or {}

    loc = totals.get("loc", 0)
    nosec = totals.get("nosec", 0)
    severity_counts = _severity_counts(results)
    total_issues = len(results)
    files = sorted({Path(issue.get("filename", "")).name for issue in results if issue.get("filename")})
    files_text = ", ".join(files) if files else "No files found"

    guidance = [
        "Start with the High severity issues at the top of the table.",
        "Use the File and Line columns to jump to the exact code.",
        "Read the short explanation to understand why Bandit flagged the code.",
        "Rerun the scan after fixing the code to refresh this dashboard.",
    ]

    rows = []
    for issue in results:
        severity = issue.get("issue_severity", "LOW")
        test_name = issue.get("test_name", "unknown_issue")
        test_id = issue.get("test_id", "N/A")
        issue_text = issue.get("issue_text", "No description available.")
        filename = issue.get("filename", "Unknown file")
        line_number = issue.get("line_number", "N/A")
        confidence = issue.get("issue_confidence", "UNKNOWN")
        more_info = issue.get("more_info", "")
        rows.append(
            f"""
            <tr>
              <td><span class="badge badge-{escape(severity.lower())}">{escape(severity)}</span></td>
              <td>{escape(test_name)}</td>
              <td>{escape(test_id)}</td>
              <td>{escape(issue_text)}</td>
              <td>{escape(filename)}</td>
              <td>{escape(str(line_number))}</td>
              <td>{escape(confidence)}</td>
              <td>{f'<a href="{escape(more_info)}" target="_blank" rel="noreferrer">Bandit docs</a>' if more_info else '-'}</td>
            </tr>
            """
        )

    if not rows:
        rows_html = '<tr><td colspan="8" class="empty">No vulnerabilities detected. Bandit found nothing to report.</td></tr>'
    else:
        rows_html = "\n".join(rows)

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Bandit Dashboard</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --panel: #ffffff;
      --panel-soft: #f9fbff;
      --text: #1f2937;
      --muted: #5b6472;
      --border: #dbe3ee;
      --blue: #2f6fed;
      --green: #15803d;
      --amber: #b45309;
      --red: #b91c1c;
      --shadow: 0 10px 30px rgba(31, 41, 55, 0.08);
    }}

    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}

    .container {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 24px;
    }}

    .header {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 24px;
      box-shadow: var(--shadow);
      margin-bottom: 18px;
    }}

    h1 {{
      margin: 0;
      font-size: 30px;
    }}

    .subtitle {{
      margin: 10px 0 0;
      color: var(--muted);
      line-height: 1.6;
      max-width: 900px;
    }}

    .meta {{
      margin-top: 14px;
      color: var(--muted);
      font-size: 14px;
    }}

    .cards {{
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }}

    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
      box-shadow: var(--shadow);
    }}

    .card .label {{
      color: var(--muted);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}

    .card .value {{
      margin-top: 8px;
      font-size: 28px;
      font-weight: 700;
    }}

    .card.high .value {{ color: var(--red); }}
    .card.medium .value {{ color: var(--amber); }}
    .card.low .value {{ color: var(--blue); }}
    .card.total .value {{ color: var(--green); }}

    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      box-shadow: var(--shadow);
      margin-bottom: 18px;
    }}

    .panel h2 {{
      margin: 0 0 12px;
      font-size: 20px;
    }}

    .guide ol {{
      margin: 0;
      padding-left: 20px;
      line-height: 1.7;
      color: var(--text);
    }}

    .guide li + li {{ margin-top: 6px; }}

    .chips {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }}

    .chip {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      background: var(--panel-soft);
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 13px;
    }}

    .table-wrap {{ overflow-x: auto; }}

    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 1050px;
    }}

    th, td {{
      border-bottom: 1px solid var(--border);
      padding: 12px 10px;
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}

    th {{
      background: var(--panel-soft);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
    }}

    .badge {{
      display: inline-block;
      padding: 5px 10px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 12px;
      color: #fff;
    }}

    .badge-high {{ background: var(--red); }}
    .badge-medium {{ background: var(--amber); }}
    .badge-low {{ background: var(--blue); }}

    .empty {{
      text-align: center;
      color: var(--muted);
      padding: 24px 12px;
    }}

    a {{ color: var(--blue); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    @media (max-width: 1100px) {{
      .cards {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    }}

    @media (max-width: 720px) {{
      .container {{ padding: 14px; }}
      .cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      h1 {{ font-size: 24px; }}
    }}
  </style>
</head>
<body>
  <main class="container">
    <section class="header">
      <h1>Bandit Dashboard</h1>
      <p class="subtitle">A simple dashboard for beginners. It shows the most important Bandit findings first, explains what they mean, and lets you jump to the exact file and line number.</p>
      <div class="meta">Files scanned: {escape(files_text)} | Last generated from Bandit JSON report</div>
    </section>

    <section class="cards">
      <div class="card total"><div class="label">Total issues</div><div class="value">{total_issues}</div></div>
      <div class="card high"><div class="label">High</div><div class="value">{severity_counts['HIGH']}</div></div>
      <div class="card medium"><div class="label">Medium</div><div class="value">{severity_counts['MEDIUM']}</div></div>
      <div class="card low"><div class="label">Low</div><div class="value">{severity_counts['LOW']}</div></div>
      <div class="card"><div class="label">Lines of code</div><div class="value">{loc}</div></div>
      <div class="card"><div class="label">#nosec skipped</div><div class="value">{nosec}</div></div>
    </section>

    <section class="panel guide">
      <h2>How to use this dashboard</h2>
      <ol>
        {''.join(f'<li>{escape(item)}</li>' for item in guidance)}
      </ol>
      <div class="chips">
        <span class="chip"><strong>High</strong> = fix first</span>
        <span class="chip"><strong>Medium</strong> = fix soon</span>
        <span class="chip"><strong>Low</strong> = review when you can</span>
      </div>
    </section>

    <section class="panel">
      <h2>Findings</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule</th>
              <th>ID</th>
              <th>What Bandit found</th>
              <th>File</th>
              <th>Line</th>
              <th>Confidence</th>
              <th>More info</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>"""

    html_path.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    build_report(Path("bandit-report.json"), Path("bandit-report.html"))
