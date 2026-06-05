"""CSS styles for generic HTML reports."""

REPORT_CSS = r"""
:root {
  --bg: #f6f7f9;
  --card: #ffffff;
  --text: #1a1d29;
  --text-secondary: #4a4f5e;
  --muted: #7a7f8f;
  --border: #e2e4ea;
  --border-light: #edf0f5;
  --accent: #3451e2;
  --accent-soft: #eef1fd;
  --accent-glow: rgba(52,81,226,0.08);
  --critical: #d92d3b;
  --critical-bg: #fef0f1;
  --high: #e8640c;
  --high-bg: #fef6ee;
  --medium: #b78b08;
  --medium-bg: #fdfaec;
  --low: #1f9254;
  --low-bg: #edf7f1;
  --info: #5a6175;
  --info-bg: #f3f4f7;
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
  --shadow-md: 0 2px 8px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04);
  --radius: 10px;
  --radius-sm: 6px;
  --font: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  --font-display: "Inter Display", system-ui, -apple-system, sans-serif;
  --mono: "Cascadia Code", "Fira Code", "JetBrains Mono", "SF Mono", Consolas, monospace;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b0d14;
    --card: #141722;
    --text: #e6e7ec;
    --text-secondary: #b0b4c2;
    --muted: #6f748a;
    --border: #232738;
    --border-light: #1c1f2e;
    --accent: #678af5;
    --accent-soft: #1a1f35;
    --accent-glow: rgba(103,138,245,0.1);
    --critical: #f0656e;
    --critical-bg: #2a1518;
    --high: #f08c4a;
    --high-bg: #2a1d14;
    --medium: #d9b72b;
    --medium-bg: #252214;
    --low: #3db871;
    --low-bg: #141f18;
    --info: #7a8099;
    --info-bg: #1a1c25;
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.2);
    --shadow-md: 0 2px 12px rgba(0,0,0,0.25);
  }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  line-height: 1.72;
  padding: 2.5rem 1.5rem;
  -webkit-font-smoothing: antialiased;
}

.container { max-width: 920px; margin: 0 auto; }

/* ── Header ── */
header {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 2.25rem 2.5rem;
  margin-bottom: 1.75rem;
  box-shadow: var(--shadow-sm);
}

header h1 {
  font-family: var(--font-display);
  font-size: 1.85rem;
  font-weight: 800;
  letter-spacing: -0.025em;
  line-height: 1.2;
  margin-bottom: 0.6rem;
  color: var(--text);
}

header .meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.6rem;
  font-size: 0.84rem;
  color: var(--muted);
}

header .meta .sep { color: var(--border); }

header .meta .tag {
  display: inline-flex;
  align-items: center;
  background: var(--accent-soft);
  color: var(--accent);
  padding: 0.2rem 0.7rem;
  border-radius: 99px;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.01em;
}

header .target-info {
  margin-top: 1rem;
  padding: 0.65rem 1rem;
  background: var(--bg);
  border-radius: var(--radius-sm);
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--muted);
  word-break: break-all;
  border: 1px solid var(--border-light);
}

/* ── Summary ── */
.summary {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.75rem 2.5rem;
  margin-bottom: 1.75rem;
  box-shadow: var(--shadow-sm);
}

.summary h2 {
  font-size: 1rem;
  font-weight: 700;
  margin-bottom: 0.6rem;
  color: var(--accent);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-size: 0.78rem;
}

.summary p { color: var(--text-secondary); }

/* ── Sections ── */
.section {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 1.25rem;
  overflow: hidden;
  box-shadow: var(--shadow-sm);
  transition: box-shadow 0.15s;
}

.section:hover { box-shadow: var(--shadow-md); }

.section-header {
  display: flex;
  align-items: center;
  padding: 1.1rem 1.75rem;
  cursor: pointer;
  user-select: none;
  border-bottom: 1px solid transparent;
  transition: background 0.12s;
}

.section-header:hover { background: var(--bg); }

.section-body:not(.collapsed) + .section-header,
.section:has(.section-body:not(.collapsed)) .section-header {
  border-bottom-color: var(--border-light);
}

.section-header .toggle {
  margin-right: 0.5rem;
  font-size: 0.65rem;
  color: var(--muted);
  transition: transform 0.2s;
  width: 1.2rem;
  text-align: center;
  flex-shrink: 0;
}

.section-header h3 {
  font-size: 1rem;
  font-weight: 650;
  color: var(--text);
}

.section-body {
  padding: 1.5rem 1.75rem;
}

.section-body.collapsed { display: none; }

.section-body .intro {
  color: var(--muted);
  margin-bottom: 1rem;
  font-size: 0.9rem;
}

/* ── Findings ── */
.finding {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1.1rem 1.25rem;
  margin-bottom: 0.75rem;
  border-left: 3px solid var(--border);
  transition: border-color 0.15s;
}

.finding:last-child { margin-bottom: 0; }

.finding-header {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  margin-bottom: 0.5rem;
  flex-wrap: wrap;
}

.severity {
  font-size: 0.68rem;
  font-weight: 700;
  text-transform: uppercase;
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  letter-spacing: 0.05em;
  flex-shrink: 0;
}

.sev-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
.sev-high     { background: var(--high-bg);     color: var(--high);     border: 1px solid var(--high); }
.sev-medium   { background: var(--medium-bg);   color: var(--medium);   border: 1px solid var(--medium); }
.sev-low      { background: var(--low-bg);      color: var(--low);      border: 1px solid var(--low); }
.sev-info     { background: var(--info-bg);     color: var(--info);     border: 1px solid var(--info); }

/* severity left border on finding card */
.finding:has(.sev-critical) { border-left-color: var(--critical); }
.finding:has(.sev-high)     { border-left-color: var(--high); }
.finding:has(.sev-medium)   { border-left-color: var(--medium); }
.finding:has(.sev-low)      { border-left-color: var(--low); }

.finding-location {
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--muted);
  background: var(--bg);
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
}

.finding-desc { margin-bottom: 0.4rem; color: var(--text-secondary); }
.finding-desc p { margin-bottom: 0.35rem; }

.finding-code { margin: 0.5rem 0; }

.finding-remediation {
  margin-top: 0.5rem;
  padding: 0.7rem 0.9rem;
  background: var(--low-bg);
  border-radius: var(--radius-sm);
  font-size: 0.88rem;
  border: 1px solid color-mix(in srgb, var(--low) 20%, transparent);
}

.finding-remediation strong { color: var(--low); }

/* ── Code blocks ── */
.code-block {
  margin: 0.75rem 0;
  border-radius: var(--radius-sm);
  overflow: hidden;
  border: 1px solid var(--border);
  background: var(--bg);
}

.code-block .code-lang {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  padding: 0.45rem 1rem;
  background: var(--card);
  border-bottom: 1px solid var(--border);
}
.code-block .code-lang::before {
  content: "";
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--border);
  box-shadow: 10px 0 0 var(--border), 20px 0 0 var(--border);
}

.code-block pre {
  padding: 1.1rem;
  overflow-x: auto;
  font-family: var(--mono);
  font-size: 0.82rem;
  line-height: 1.6;
  tab-size: 4;
  background: var(--bg);
}

/* ── Tables ── */
.table-wrap {
  overflow-x: auto;
  margin: 0.75rem 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
}

.table-wrap table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.88rem;
}

.table-wrap caption {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--muted);
  padding: 0.6rem 1rem;
  text-align: left;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
}

.table-wrap th {
  text-align: left;
  font-weight: 650;
  font-size: 0.76rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  padding: 0.55rem 0.9rem;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
}

.table-wrap td {
  padding: 0.5rem 0.9rem;
  border-bottom: 1px solid var(--border-light);
  color: var(--text-secondary);
}

.table-wrap tbody tr:last-child td { border-bottom: none; }
.table-wrap tbody tr:nth-child(even) td { background: rgba(0,0,0,0.015); }
.table-wrap tbody tr:hover td { background: var(--accent-soft); }

/* ── Timeline ── */
.timeline { margin: 0.5rem 0; }

.timeline-item {
  display: flex;
  gap: 1rem;
  padding: 0.55rem 0;
  border-bottom: 1px solid var(--border-light);
  align-items: baseline;
}

.timeline-item:last-child { border-bottom: none; }

.timeline-time {
  font-family: var(--mono);
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--accent);
  min-width: 90px;
  flex-shrink: 0;
  background: var(--accent-soft);
  padding: 0.15rem 0.6rem;
  border-radius: 4px;
  text-align: center;
}

/* ── Comparison ── */
.comparison {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.comparison .comp-panel {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  overflow: hidden;
}

.comp-panel .comp-title {
  font-size: 0.82rem;
  font-weight: 650;
  padding: 0.5rem 0.9rem;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.comp-panel .comp-body {
  padding: 0.9rem;
  font-size: 0.88rem;
  color: var(--text-secondary);
}

.comp-panel .comp-body pre {
  font-family: var(--mono);
  font-size: 0.8rem;
  overflow-x: auto;
  background: var(--bg);
  padding: 0.6rem;
  border-radius: 4px;
}

/* ── Appendix ── */
.appendix {
  margin-top: 2rem;
  padding: 1.75rem 2.5rem;
  background: var(--card);
  border: 1px dashed var(--border);
  border-radius: var(--radius);
  font-size: 0.88rem;
  color: var(--muted);
}

.appendix h2 {
  font-size: 0.95rem;
  font-weight: 700;
  margin-bottom: 0.5rem;
  color: var(--text);
}

/* ── Footer ── */
footer {
  text-align: center;
  font-size: 0.75rem;
  color: var(--muted);
  margin-top: 2.5rem;
  opacity: 0.7;
}

/* ── Typography ── */
h1, h2, h3, h4 { color: var(--text); }
h1 { font-size: 1.5rem; font-weight: 750; letter-spacing: -0.02em; margin-bottom: 0.5rem; }
h2 { font-size: 1.2rem; font-weight: 700; margin: 1.25rem 0 0.5rem; }
h3 { font-size: 1.05rem; font-weight: 650; margin: 1rem 0 0.4rem; }
h4 { font-size: 0.95rem; font-weight: 650; margin: 0.75rem 0 0.3rem; }

p { margin-bottom: 0.6rem; color: var(--text-secondary); }

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

code {
  font-family: var(--mono);
  font-size: 0.85em;
  background: var(--bg);
  padding: 0.12em 0.4em;
  border-radius: 3px;
  border: 1px solid var(--border-light);
  color: var(--critical);
}

pre code {
  border: none;
  padding: 0;
  color: inherit;
  background: transparent;
}

blockquote {
  border-left: 3px solid var(--accent);
  margin: 0.6rem 0;
  padding: 0.4rem 1rem;
  background: var(--accent-soft);
  border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  color: var(--text-secondary);
}

ul, ol { padding-left: 1.5rem; margin-bottom: 0.6rem; color: var(--text-secondary); }
li { margin-bottom: 0.2rem; }

hr {
  border: none;
  border-top: 1px solid var(--border-light);
  margin: 1rem 0;
}

/* ── Responsive ── */
@media (max-width: 640px) {
  body { padding: 1.25rem 0.75rem; }
  .comparison { grid-template-columns: 1fr; }
  header { padding: 1.5rem; }
  .section-header { padding: 0.85rem 1.25rem; }
  .section-body { padding: 1rem 1.25rem; }
  .summary { padding: 1.25rem 1.5rem; }
}

@media print {
  body { padding: 0; font-size: 10.5pt; background: #fff; }
  .section-body.collapsed { display: block; }
  .section-header { cursor: default; }
  .section { box-shadow: none; break-inside: avoid; }
  .code-block .code-lang::before { display: none; }
}
"""
