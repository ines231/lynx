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
