// Small dependency-free SVG charts (the platform must work offline).
// Every function returns an HTML/SVG string; the caller sets innerHTML.
// All dynamic text goes through `esc` (defined in app.js).

const SVG_NS_W = 640;

function niceTicks(max, count = 4) {
  if (!(max > 0)) return [0];
  const raw = max / count;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) || raw;
  const ticks = [];
  // always end on a tick >= max so that the tallest bar fits in the plot
  for (let v = 0; ; v += step) {
    ticks.push(v);
    if (v >= max) break;
  }
  return ticks;
}

function compactNumber(v) {
  const abs = Math.abs(v);
  if (abs >= 1e6) return (v / 1e6).toLocaleString("fr-FR", { maximumFractionDigits: 1 }) + " M";
  if (abs >= 1e3) return (v / 1e3).toLocaleString("fr-FR", { maximumFractionDigits: 1 }) + " k";
  return v.toLocaleString("fr-FR", { maximumFractionDigits: 0 });
}

// Histogram of simulated annual losses with ALE / VaR 95 / VaR 99 markers.
// h = { edges[n+1], counts[n], annual_loss_expectancy, value_at_risk_95, value_at_risk_99, ... }
function lossHistogramSvg(h, symbol) {
  if (!h || !h.counts || !h.counts.length) {
    return '<div class="empty">Aucune perte simulée pour cet événement.</div>';
  }

  const W = SVG_NS_W, H = 280;
  const m = { l: 52, r: 16, t: 18, b: 44 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const lo = h.edges[0], hi = h.edges[h.edges.length - 1];
  const x = (v) => m.l + ((Math.min(Math.max(v, lo), hi) - lo) / (hi - lo)) * iw;
  const maxCount = Math.max(...h.counts, 1);
  const yTicks = niceTicks(maxCount, 4);
  const yMax = yTicks[yTicks.length - 1] || maxCount;
  const y = (c) => m.t + ih - (c / yMax) * ih;
  const bw = iw / h.counts.length;
  const total = h.loss_years || h.counts.reduce((a, b) => a + b, 0);

  const bars = h.counts.map((c, i) => {
    const x0 = m.l + i * bw;
    const from = h.edges[i], to = h.edges[i + 1];
    const last = i === h.counts.length - 1;
    const label = `${compactNumber(from)}${last ? "+" : " – " + compactNumber(to)} ${symbol} : ` +
      `${c} année(s) simulée(s) (${((c / total) * 100).toFixed(1)} %)`;
    return `<rect class="hbar" x="${(x0 + 1).toFixed(1)}" y="${y(c).toFixed(1)}" width="${Math.max(bw - 2, 1).toFixed(1)}"
      height="${(m.t + ih - y(c)).toFixed(1)}" rx="2"><title>${esc(label)}</title></rect>`;
  }).join("");

  const grid = yTicks.map((t) =>
    `<line class="hgrid" x1="${m.l}" x2="${W - m.r}" y1="${y(t).toFixed(1)}" y2="${y(t).toFixed(1)}"/>
     <text class="haxis" x="${m.l - 8}" y="${(y(t) + 4).toFixed(1)}" text-anchor="end">${compactNumber(t)}</text>`
  ).join("");

  const xTicks = niceTicks(hi, 5).filter((v) => v <= hi)
    .map((v) => `<text class="haxis" x="${x(v).toFixed(1)}" y="${H - m.b + 18}" text-anchor="middle">${compactNumber(v)}</text>`)
    .join("");

  // markers, staggered vertically so labels never overlap
  const markers = [
    { v: h.annual_loss_expectancy, name: "ALE", cls: "m-ale" },
    { v: h.value_at_risk_95, name: "VaR 95 %", cls: "m-var95" },
    { v: h.value_at_risk_99, name: "VaR 99 %", cls: "m-var99" }
  ].filter((k) => typeof k.v === "number" && k.v > 0);

  const lines = markers.map((k, i) => {
    const inRange = k.v <= hi;
    const px = x(k.v);
    const anchor = px > W - m.r - 150 ? "end" : "start";
    const tx = anchor === "end" ? px - 5 : px + 5;
    return `<g class="marker ${k.cls}">
      <line x1="${px.toFixed(1)}" x2="${px.toFixed(1)}" y1="${m.t}" y2="${m.t + ih}"/>
      <text x="${tx.toFixed(1)}" y="${m.t + 12 + i * 14}" text-anchor="${anchor}">${esc(k.name)} ${esc(compactNumber(k.v))} ${esc(symbol)}${inRange ? "" : " →"}</text>
    </g>`;
  }).join("");

  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img"
      aria-label="Distribution des pertes annuelles simulées (Monte-Carlo)">
    ${grid}${bars}${lines}
    <line class="haxisline" x1="${m.l}" x2="${W - m.r}" y1="${m.t + ih}" y2="${m.t + ih}"/>
    ${xTicks}
    <text class="haxis title" x="${(m.l + iw / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle">Perte annuelle simulée (${esc(symbol)})</text>
    <text class="haxis title" transform="translate(12 ${(m.t + ih / 2).toFixed(1)}) rotate(-90)" text-anchor="middle">Années simulées</text>
  </svg>`;
}

// Observed (attack window) vs expected (baseline) counts per event type, with the
// share of the chi-square statistic each category is responsible for.
// rows = chi_square.categories
function baselineVsObservedSvg(rows) {
  if (!rows || !rows.length) {
    return '<div class="empty">Pas de détail par catégorie pour ce test.</div>';
  }

  const sorted = [...rows].sort((a, b) => b.contribution - a.contribution);
  const W = SVG_NS_W, rowH = 46;
  const m = { l: 138, r: 78, t: 8, b: 34 };
  const H = m.t + m.b + sorted.length * rowH;
  const iw = W - m.l - m.r;
  const maxV = Math.max(...sorted.flatMap((r) => [r.observed, r.expected]), 1);
  const ticks = niceTicks(maxV, 4);
  const top = ticks[ticks.length - 1] || maxV;
  const x = (v) => m.l + (v / top) * iw;
  const fmt = (v) => v.toLocaleString("fr-FR", { maximumFractionDigits: 1 });

  const grid = ticks.map((t) =>
    `<line class="hgrid" x1="${x(t).toFixed(1)}" x2="${x(t).toFixed(1)}" y1="${m.t}" y2="${H - m.b}"/>
     <text class="haxis" x="${x(t).toFixed(1)}" y="${H - m.b + 16}" text-anchor="middle">${compactNumber(t)}</text>`
  ).join("");

  const bars = sorted.map((r, i) => {
    const y0 = m.t + i * rowH;
    const tip = `${r.category} : attendu ${fmt(r.expected)}, observé ${r.observed}, ` +
      `contribution au χ² = ${fmt(r.contribution)} (${(r.share * 100).toFixed(1)} %)` +
      (r.new ? " — catégorie absente de la baseline" : "");
    const hot = r.share >= 0.25;
    return `<g class="cat-row"><title>${esc(tip)}</title>
      <text class="cat-name" x="${m.l - 10}" y="${y0 + 20}" text-anchor="end">${esc(r.category)}${r.new ? " ★" : ""}</text>
      <rect class="bar-exp" x="${m.l}" y="${y0 + 6}" width="${Math.max(x(r.expected) - m.l, 1).toFixed(1)}" height="11" rx="2"/>
      <rect class="bar-obs" x="${m.l}" y="${y0 + 20}" width="${Math.max(x(r.observed) - m.l, r.observed > 0 ? 1 : 0).toFixed(1)}" height="11" rx="2"/>
      <text class="cat-val" x="${(x(Math.max(r.expected, r.observed)) + 6).toFixed(1)}" y="${y0 + 22}">${r.observed} / ${fmt(r.expected)}</text>
      <text class="cat-share ${hot ? "hot" : ""}" x="${W - 4}" y="${y0 + 22}" text-anchor="end">${(r.share * 100).toFixed(0)} %</text>
    </g>`;
  }).join("");

  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img"
      aria-label="Comptes observés et attendus par type d'événement">
    ${grid}${bars}
    <line class="haxisline" x1="${m.l}" x2="${m.l}" y1="${m.t}" y2="${H - m.b}"/>
    <text class="haxis title" x="${W - 4}" y="${H - 6}" text-anchor="end">part du χ²</text>
  </svg>`;
}

// Donut of the number of events per priority. rows = [{label, value, color}]
function donutSvg(rows, centerLabel) {
  const data = rows.filter((r) => r.value > 0);
  const total = data.reduce((a, r) => a + r.value, 0);
  if (!total) return '<div class="empty">Aucun événement.</div>';

  const S = 180, cx = S / 2, cy = S / 2, R = 78, r = 50;
  let angle = -Math.PI / 2;
  const point = (rad, a) => [cx + rad * Math.cos(a), cy + rad * Math.sin(a)];

  const arcs = data.map((d) => {
    const sweep = (d.value / total) * Math.PI * 2;
    const full = data.length === 1;
    const a0 = angle, a1 = angle + (full ? sweep - 0.0001 : sweep);
    angle += sweep;
    const [x0, y0] = point(R, a0), [x1, y1] = point(R, a1);
    const [x2, y2] = point(r, a1), [x3, y3] = point(r, a0);
    const large = sweep > Math.PI ? 1 : 0;
    const path = `M${x0.toFixed(2)} ${y0.toFixed(2)} A${R} ${R} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)} ` +
      `L${x2.toFixed(2)} ${y2.toFixed(2)} A${r} ${r} 0 ${large} 0 ${x3.toFixed(2)} ${y3.toFixed(2)} Z`;
    const tip = `${d.label} : ${d.value} événement(s) (${((d.value / total) * 100).toFixed(0)} %)`;
    return `<path class="donut-seg" d="${path}" fill="${d.color}"><title>${esc(tip)}</title></path>`;
  }).join("");

  const legend = data.map((d) =>
    `<li><i style="background:${d.color}"></i><span>${esc(d.label)}</span><b>${d.value}</b></li>`
  ).join("");

  return `<div class="donut">
    <svg viewBox="0 0 ${S} ${S}" role="img" aria-label="Répartition des événements par priorité">
      ${arcs}
      <text class="donut-total" x="${cx}" y="${cy + 2}" text-anchor="middle">${total}</text>
      <text class="donut-label" x="${cx}" y="${cy + 18}" text-anchor="middle">${esc(centerLabel || "événements")}</text>
    </svg>
    <ul class="donut-legend">${legend}</ul>
  </div>`;
}

// ATT&CK matrix: the 14 enterprise tactics as columns, the detected techniques as
// highlighted cells. techniques = [{technique_id, name, tactics[], url, score, ...}]
const ATTACK_TACTICS = [
  ["reconnaissance", "Reconnaissance"], ["resource-development", "Resource Dev."],
  ["initial-access", "Initial Access"], ["execution", "Execution"],
  ["persistence", "Persistence"], ["privilege-escalation", "Privilege Esc."],
  ["defense-evasion", "Defense Evasion"], ["credential-access", "Credential Access"],
  ["discovery", "Discovery"], ["lateral-movement", "Lateral Movement"],
  ["collection", "Collection"], ["command-and-control", "C2"],
  ["exfiltration", "Exfiltration"], ["impact", "Impact"]
];

function attackMatrixHtml(techniques) {
  const list = techniques || [];
  const known = new Set(ATTACK_TACTICS.map((t) => t[0]));
  const columns = ATTACK_TACTICS.map(([key, label]) => {
    const cells = list.filter((t) => (t.tactics || []).includes(key));
    const body = cells.map((t) => {
      const tip = `${t.technique_id} ${t.name || ""}` +
        (t.event_types && t.event_types.length ? ` — événement(s) : ${t.event_types.join(", ")}` : "") +
        (t.score != null ? ` — pertinence ${t.score}` : "");
      const href = /^https:\/\/attack\.mitre\.org\//.test(t.url || "") ? t.url : null;
      const inner = `<b>${esc(t.technique_id)}</b><span>${esc(t.name || "")}</span>`;
      return href
        ? `<a class="mx-cell" href="${esc(href)}" target="_blank" rel="noopener noreferrer" title="${esc(tip)}">${inner}</a>`
        : `<div class="mx-cell" title="${esc(tip)}">${inner}</div>`;
    }).join("");
    return `<div class="mx-col ${cells.length ? "hit" : ""}">
      <div class="mx-head">${esc(label)}<em>${cells.length || ""}</em></div>
      ${body}
    </div>`;
  }).join("");

  const orphans = list.filter((t) => !(t.tactics || []).some((x) => known.has(x)));
  const note = orphans.length
    ? `<p class="muted">${orphans.length} technique(s) sans tactique reconnue : ${orphans.map((t) => esc(t.technique_id)).join(", ")}.</p>`
    : "";
  return `<div class="mx-scroll"><div class="mx">${columns}</div></div>${note}`;
}
