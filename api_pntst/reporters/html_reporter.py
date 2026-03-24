"""HTML report generator — produces a self-contained, interactive HTML report."""

import json
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Environment, BaseLoader

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_COLOR = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6b7280",
}

# ── Jinja2 HTML template (self-contained) ─────────────────────────────────────
_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>api-pntst Report — {{ meta.target }}</title>
  <style>
    :root {
      --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
      --border: #475569; --text: #e2e8f0; --text-muted: #94a3b8;
      --critical: #ef4444; --high: #f97316; --medium: #eab308;
      --low: #3b82f6; --info: #6b7280; --success: #22c55e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; }

    /* ── Layout ── */
    header { background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); padding: 2rem; border-bottom: 1px solid var(--border); }
    header h1 { font-size: 1.8rem; font-weight: 700; color: #38bdf8; }
    header p { color: var(--text-muted); margin-top: 0.25rem; }
    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }

    .container { max-width: 1280px; margin: 0 auto; padding: 2rem; }

    /* ── Summary cards ── */
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card { background: var(--surface); border-radius: 12px; padding: 1.25rem; text-align: center; border: 1px solid var(--border); }
    .card .count { font-size: 2.5rem; font-weight: 800; line-height: 1; }
    .card .label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-top: 0.4rem; }

    /* ── Chart ── */
    .chart-wrap { background: var(--surface); border-radius: 12px; padding: 1.5rem; border: 1px solid var(--border); margin-bottom: 2rem; display: flex; align-items: center; justify-content: center; min-height: 220px; }

    /* ── Endpoints table ── */
    .section-title { font-size: 1.1rem; font-weight: 700; margin: 2rem 0 1rem; color: #38bdf8; border-left: 4px solid #38bdf8; padding-left: 0.75rem; }
    table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 12px; overflow: hidden; border: 1px solid var(--border); margin-bottom: 2rem; }
    th { background: var(--surface2); padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
    td { padding: 0.7rem 1rem; border-top: 1px solid var(--border); font-size: 0.875rem; }
    tr:hover td { background: rgba(255,255,255,0.03); }
    code { background: var(--surface2); padding: 0.1rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.85em; }

    /* ── Severity badges ── */
    .sev-critical { background: rgba(239,68,68,.2); color: var(--critical); border: 1px solid var(--critical); }
    .sev-high     { background: rgba(249,115,22,.2); color: var(--high); border: 1px solid var(--high); }
    .sev-medium   { background: rgba(234,179,8,.2);  color: var(--medium); border: 1px solid var(--medium); }
    .sev-low      { background: rgba(59,130,246,.2); color: var(--low); border: 1px solid var(--low); }
    .sev-info     { background: rgba(107,114,128,.2);color: var(--info); border: 1px solid var(--info); }

    /* ── Filter bar ── */
    .filter-bar { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1.25rem; }
    .filter-btn { padding: 0.35rem 0.9rem; border-radius: 9999px; border: 1px solid var(--border);
                  background: var(--surface); color: var(--text); cursor: pointer; font-size: 0.8rem; transition: all .2s; }
    .filter-btn.active, .filter-btn:hover { background: #38bdf8; color: #0f172a; border-color: #38bdf8; }

    /* ── Finding cards ── */
    .finding { background: var(--surface); border-radius: 12px; border: 1px solid var(--border);
               margin-bottom: 1.25rem; overflow: hidden; }
    .finding-header { display: flex; align-items: center; gap: 0.75rem; padding: 1rem 1.25rem;
                      cursor: pointer; user-select: none; }
    .finding-header:hover { background: rgba(255,255,255,0.04); }
    .finding-title { font-weight: 600; flex: 1; }
    .finding-endpoint { font-size: 0.8rem; color: var(--text-muted); font-family: monospace; }
    .chevron { transition: transform .3s; color: var(--text-muted); }
    .finding.open .chevron { transform: rotate(180deg); }
    .finding-body { display: none; padding: 1.25rem; border-top: 1px solid var(--border); }
    .finding.open .finding-body { display: block; }

    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
    @media (max-width: 640px) { .detail-grid { grid-template-columns: 1fr; } }
    .detail-box { background: var(--surface2); border-radius: 8px; padding: 1rem; }
    .detail-box h4 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.5rem; }
    .detail-box pre { white-space: pre-wrap; word-break: break-all; font-size: 0.82rem; font-family: monospace; }

    .remediation { background: rgba(34,197,94,.08); border: 1px solid rgba(34,197,94,.3);
                   border-radius: 8px; padding: 1rem; margin-top: 1rem; }
    .remediation h4 { color: var(--success); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }

    .refs { margin-top: 1rem; }
    .refs h4 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.4rem; }
    .refs a { color: #38bdf8; font-size: 0.85rem; display: block; text-decoration: none; }
    .refs a:hover { text-decoration: underline; }

    /* ── Method badges ── */
    .method { font-family: monospace; font-weight: 700; font-size: 0.8rem; padding: 0.15rem 0.5rem; border-radius: 4px; }
    .m-GET    { background: rgba(34,197,94,.2); color: #22c55e; }
    .m-POST   { background: rgba(59,130,246,.2); color: #3b82f6; }
    .m-PUT    { background: rgba(234,179,8,.2);  color: #eab308; }
    .m-PATCH  { background: rgba(168,85,247,.2); color: #a855f7; }
    .m-DELETE { background: rgba(239,68,68,.2);  color: #ef4444; }
    .m-OTHER  { background: rgba(107,114,128,.2);color: #6b7280; }

    footer { text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 2rem; }
  </style>
</head>
<body>

<header>
  <div style="max-width:1280px;margin:0 auto;">
    <h1>🔐 api-pntst Security Report</h1>
    <p>
      Target: <strong style="color:#38bdf8">{{ meta.target }}</strong> &nbsp;·&nbsp;
      Scanned: <strong>{{ meta.scanned_at[:19]|replace("T"," ") }} UTC</strong> &nbsp;·&nbsp;
      Endpoints: <strong>{{ meta.endpoint_count }}</strong>
    </p>
  </div>
</header>

<div class="container">

  <!-- ── Summary cards ── -->
  <div class="cards">
    <div class="card">
      <div class="count" style="color:#e2e8f0">{{ counts.total }}</div>
      <div class="label">Total Findings</div>
    </div>
    {% for sev in ['critical','high','medium','low','info'] %}
    <div class="card">
      <div class="count" style="color:{{ colors[sev] }}">{{ counts[sev] }}</div>
      <div class="label">{{ sev|capitalize }}</div>
    </div>
    {% endfor %}
  </div>

  <!-- ── SVG Donut chart (no external dependencies) ── -->
  {% if counts.total > 0 %}
  <div class="chart-wrap">
    <svg id="sevChart" viewBox="0 0 200 200" width="200" height="200" style="flex-shrink:0">
      <!-- drawn by inline JS below -->
    </svg>
    <div id="chart-legend" style="display:flex;flex-direction:column;justify-content:center;gap:0.6rem;padding-left:2rem"></div>
  </div>
  {% endif %}

  <!-- ── Discovered endpoints ── -->
  <div class="section-title">Discovered Endpoints ({{ endpoints|length }})</div>
  <table>
    <thead>
      <tr><th>Method</th><th>Path</th><th>Source</th><th>Summary</th></tr>
    </thead>
    <tbody>
    {% for ep in endpoints %}
      <tr>
        <td><span class="method m-{{ ep.method if ep.method in ['GET','POST','PUT','PATCH','DELETE'] else 'OTHER' }}">{{ ep.method }}</span></td>
        <td><code>{{ ep.path }}</code></td>
        <td>{{ ep.get('source','—') }}</td>
        <td style="color:var(--text-muted);font-size:0.8rem">{{ ep.get('summary','') or ep.get('operation_id','') }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- ── Findings ── -->
  <div class="section-title">Security Findings ({{ findings|length }})</div>

  {% if findings %}
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('all', this)">All ({{ counts.total }})</button>
    {% for sev in ['critical','high','medium','low','info'] %}
    {% if counts[sev] > 0 %}
    <button class="filter-btn" onclick="filterFindings('{{ sev }}', this)" style="border-color:{{ colors[sev] }}">
      {{ sev|capitalize }} ({{ counts[sev] }})
    </button>
    {% endif %}
    {% endfor %}
  </div>

  {% for f in sorted_findings %}
  <div class="finding" data-severity="{{ f.severity }}" id="finding-{{ loop.index }}">
    <div class="finding-header" onclick="toggleFinding(this.parentElement)">
      <span class="badge sev-{{ f.severity }}">{{ f.severity|upper }}</span>
      <div style="flex:1">
        <div class="finding-title">{{ f.title }}</div>
        <div class="finding-endpoint">{{ f.scanner }} &nbsp;·&nbsp; {{ f.endpoint }}</div>
      </div>
      <svg class="chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polyline points="6 9 12 15 18 9"/>
      </svg>
    </div>
    <div class="finding-body">
      <div class="detail-grid">
        <div class="detail-box">
          <h4>Description</h4>
          <p style="font-size:0.875rem">{{ f.description }}</p>
        </div>
        {% if f.evidence %}
        <div class="detail-box">
          <h4>Evidence</h4>
          <pre>{{ f.evidence }}</pre>
        </div>
        {% endif %}
        {% if f.payload %}
        <div class="detail-box">
          <h4>Payload Used</h4>
          <pre>{{ f.payload }}</pre>
        </div>
        {% endif %}
        {% if f.status_code %}
        <div class="detail-box">
          <h4>HTTP Status</h4>
          <p style="font-size:1.5rem;font-weight:700">{{ f.status_code }}</p>
        </div>
        {% endif %}
      </div>

      <div class="remediation">
        <h4>✅ Remediation</h4>
        <p style="font-size:0.875rem">{{ f.remediation }}</p>
      </div>

      {% if f.references %}
      <div class="refs">
        <h4>References</h4>
        {% for ref in f.references %}
        <a href="{{ ref }}" target="_blank" rel="noopener noreferrer">↗ {{ ref }}</a>
        {% endfor %}
      </div>
      {% endif %}
    </div>
  </div>
  {% endfor %}

  {% else %}
  <div style="text-align:center;padding:3rem;color:var(--text-muted)">
    <div style="font-size:3rem">🎉</div>
    <p style="margin-top:1rem;font-size:1.1rem">No security findings detected.</p>
  </div>
  {% endif %}

</div><!-- /container -->

<footer>
  Generated by <strong>api-pntst</strong> · {{ meta.scanned_at[:19]|replace("T"," ") }} UTC ·
  <a href="https://github.com/Bateyjosue/api-pntst" style="color:#38bdf8">github.com/Bateyjosue/api-pntst</a>
</footer>

<script>
  // ── Inline SVG Donut Chart (no external dependencies) ──────────────────────
  (function() {
    const data = {{ chart_data | safe }};
    const labels = ['Critical','High','Medium','Low','Info'];
    const colors = ['#ef4444','#f97316','#eab308','#3b82f6','#6b7280'];
    const keys   = ['critical','high','medium','low','info'];
    const total  = keys.reduce((s, k) => s + (data[k] || 0), 0);
    if (!total) return;

    const svg = document.getElementById('sevChart');
    const cx = 100, cy = 100, r = 80, gap = 2;
    let angle = -Math.PI / 2;

    keys.forEach((k, i) => {
      const val = data[k] || 0;
      if (!val) return;
      const sweep = (val / total) * (2 * Math.PI) - (gap / r);
      const x1 = cx + r * Math.cos(angle);
      const y1 = cy + r * Math.sin(angle);
      const endAngle = angle + sweep;
      const x2 = cx + r * Math.cos(endAngle);
      const y2 = cy + r * Math.sin(endAngle);
      const large = sweep > Math.PI ? 1 : 0;

      const path = document.createElementNS('http://www.w3.org/2000/svg','path');
      path.setAttribute('d', `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`);
      path.setAttribute('fill', colors[i]);
      path.setAttribute('stroke', '#1e293b');
      path.setAttribute('stroke-width', '2');
      svg.appendChild(path);
      angle = endAngle + (gap / r);
    });

    // Centre total label
    const text = document.createElementNS('http://www.w3.org/2000/svg','text');
    text.setAttribute('x', cx); text.setAttribute('y', cy - 6);
    text.setAttribute('text-anchor','middle'); text.setAttribute('fill','#e2e8f0');
    text.setAttribute('font-size','22'); text.setAttribute('font-weight','700');
    text.textContent = total;
    svg.appendChild(text);
    const sub = document.createElementNS('http://www.w3.org/2000/svg','text');
    sub.setAttribute('x', cx); sub.setAttribute('y', cy + 14);
    sub.setAttribute('text-anchor','middle'); sub.setAttribute('fill','#94a3b8');
    sub.setAttribute('font-size','10');
    sub.textContent = 'findings';
    svg.appendChild(sub);

    // Legend
    const legend = document.getElementById('chart-legend');
    keys.forEach((k, i) => {
      if (!data[k]) return;
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:0.5rem;font-size:0.85rem';
      row.innerHTML = `<span style="width:12px;height:12px;border-radius:50%;background:${colors[i]};flex-shrink:0"></span>
        <span style="color:#94a3b8">${labels[i]}</span>
        <span style="font-weight:700;color:${colors[i]}">${data[k]}</span>`;
      legend.appendChild(row);
    });
  })();

  // ── Toggle finding detail ───────────────────────────────────────────────
  function toggleFinding(el) {
    el.classList.toggle('open');
  }

  // ── Severity filter ─────────────────────────────────────────────────────
  function filterFindings(severity, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.finding').forEach(f => {
      f.style.display = (severity === 'all' || f.dataset.severity === severity) ? '' : 'none';
    });
  }

  // Open critical findings by default
  document.querySelectorAll('.finding[data-severity="critical"], .finding[data-severity="high"]')
    .forEach(f => f.classList.add('open'));
</script>
</body>
</html>
"""


def generate_html_report(
    findings: list[dict],
    endpoints: list[dict],
    meta: dict,
    output_file: str,
) -> None:
    """Render and write the HTML report to disk."""
    _SEVERITY_ORDER_LOCAL = ["critical", "high", "medium", "low", "info"]

    counts = {s: 0 for s in _SEVERITY_ORDER_LOCAL}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    counts["total"] = sum(counts.values())

    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER_LOCAL.index(f["severity"])
        if f["severity"] in _SEVERITY_ORDER_LOCAL
        else 99,
    )

    env = Environment(loader=BaseLoader(), autoescape=False)
    template = env.from_string(_TEMPLATE)

    html = template.render(
        meta=meta,
        findings=sorted_findings,
        endpoints=endpoints,
        counts=counts,
        colors=_SEVERITY_COLOR,
        chart_data=json.dumps({s: counts[s] for s in _SEVERITY_ORDER_LOCAL}),
        sorted_findings=sorted_findings,
    )

    Path(output_file).write_text(html, encoding="utf-8")
