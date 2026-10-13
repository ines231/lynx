const API = window.location.origin;
const $ = (id) => document.getElementById(id);

// Amounts come from the API already converted into the display currency
// (TND by default); the symbol is set from the response in load().
let currencySymbol = "DT";

const money = (v) => typeof v === "number"
  ? v.toLocaleString("fr-FR", { maximumFractionDigits: 0 }) + "\u00a0" + currencySymbol
  : (v ?? "—");

const pct = (v) => typeof v === "number"
  ? (v * 100).toFixed(1) + "%"
  : (v ?? "—");

// p-values: never show 0 -- the Monte-Carlo test cannot go below 1/(n_simulations+1)
const fmtP = (v) => typeof v !== "number" ? "—"
  : (v < 0.0001 ? "< 0.0001" : v.toFixed(4));

const METHOD_LABELS = {
  asymptotic: "Asymptotique (loi du χ²)",
  monte_carlo: "Monte-Carlo (test exact)",
  degenerate: "Dégénérée"
};

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({
  "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
}[c]));

async function get(path) {
  const r = await fetch(API + path, { headers: { "Accept": "application/json" } });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`);
  return r.json();
}

function priorityClass(p) {
  const x = String(p || "").toLowerCase();
  if (x.includes("critical") || x.includes("high")) return "high";
  if (x.includes("medium")) return "medium";
  return "low";
}

function stageLabel(stage) {
  return {
    reconnaissance: "Reconnaissance",
    exploitation: "Exploitation",
    persistence: "Persistence",
    lateral_movement: "Lateral Movement",
    exfiltration: "Exfiltration"
  }[stage] || stage;
}

function renderBars(rows) {
  const top = [...rows]
    .sort((a,b) => (b.anomaly_probability || 0) - (a.anomaly_probability || 0))
    .slice(0, 5);

  $("riskBars").innerHTML = top.map(x => {
    const p = Math.min(100, Math.max(0, (x.anomaly_probability || 0) * 100));
    return `<div class="bar-row">
      <span title="${esc(x.event)}">${esc(x.event)}</span>
      <div class="bar"><i style="width:${p}%"></i></div>
      <b>${pct(x.anomaly_probability)}</b>
    </div>`;
  }).join("") || '<div class="empty">Aucune mesure disponible.</div>';
}

function chiTitle(row, chi) {
  const score = typeof row.chi_square_probability === "number"
    ? ` · score 1 − p = ${pct(row.chi_square_probability)}` : "";
  return `p-value du scénario complet (${METHOD_LABELS[chi?.method] || "méthode inconnue"})${score}`;
}

function renderChi(chi) {
  const ok = chi && typeof chi.p_value === "number";
  $("chiStat").textContent = ok ? Number(chi.chi2_statistic).toFixed(2) : "—";
  $("chiDf").textContent = ok ? chi.degrees_of_freedom : "—";
  $("chiP").textContent = fmtP(chi?.p_value);
  $("riskChiSquare").textContent = fmtP(chi?.p_value);
  $("chiMethod").textContent = METHOD_LABELS[chi?.method] || "—";

  const verdict = $("chiDecision");
  if (!ok) {
    verdict.textContent = "Test indisponible";
    verdict.className = "chi-verdict";
    $("chiNote").textContent = "Le test n'a pas pu être calculé (données ou baseline insuffisantes).";
    return;
  }

  verdict.textContent = chi.is_significant ? "H0 rejetée — écart significatif" : "H0 non rejetée";
  verdict.className = "chi-verdict " + (chi.is_significant ? "alert" : "ok");

  const parts = [
    `H0 : le scénario suit la distribution de la baseline (seuil α = ${chi.p_value_threshold}).`
  ];
  if (chi.new_categories?.length) {
    parts.push(`Types jamais vus dans la baseline : ${chi.new_categories.join(", ")}.`);
  }
  if (chi.method === "monte_carlo") {
    parts.push(`Effectifs attendus faibles (min. ${Number(chi.min_expected_count).toFixed(2)}) : p-value estimée par simulation, donc jamais inférieure à 1/10 001.`);
  }
  parts.push("Le score « 1 − p » mesure la preuve contre H0, ce n'est pas une probabilité d'attaque.");
  $("chiNote").textContent = parts.join(" ");
}

function renderRows(rows, chi) {
  const body = $("riskTable");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">Aucun événement retourné.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(x => `<tr>
    <td><strong>${esc(x.event)}</strong></td>
    <td>${esc(x.user || "—")}</td>
    <td>${pct(x.anomaly_probability)}</td>
    <td title="${esc(chiTitle(x, chi))}">${fmtP(chi?.p_value)}</td>
    <td>${money(x.annual_loss_expectancy)}</td>
    <td><span class="priority ${priorityClass(x.priority)}">${esc(x.priority || "—")}</span></td>
    <td>${esc(x.strategy || "—")}</td>
  </tr>`).join("");
}

function renderKillChain(stages) {
  const ordered = ["reconnaissance","exploitation","persistence","lateral_movement","exfiltration"];
  $("killchainStages").innerHTML = ordered.map((s, i) => {
    const active = stages.includes(s);
    return `<div class="stage ${active ? "active" : ""}">
      <b>0${i+1}</b>
      <span>${stageLabel(s)}</span>
      <small>${active ? "Observé" : "Non observé"}</small>
    </div>`;
  }).join("");
}

function renderControls(controls) {
  $("controlsList").innerHTML = (controls?.length ? controls : ["Maintenir la surveillance et compléter l’analyse."])
    .map(c => `<li>${esc(c)}</li>`).join("");
}

function renderIocs(report) {
  const iocs = report?.indicators_of_compromise || {};
  const counts = [
    ["ips","IP"],
    ["domains","Domaines"],
    ["file_hashes","Hashes"],
    ["process_names","Processus"]
  ];
  $("iocSummary").innerHTML = counts.map(([key,label]) =>
    `<div><strong>${(iocs[key] || []).length}</strong><span>${label}</span></div>`
  ).join("");
}

function renderTechniques(techniques) {
  const list = techniques?.length ? techniques : [];

  $("mitreList").innerHTML = list.map(t => {
    const name = t.name || t.description || "";
    const tactics = (t.tactics || []).join(", ");
    const terms = (t.matched_terms || []).join(", ");
    const tip = [
      tactics && `Tactique(s) ATT&CK : ${tactics}`,
      t.score != null && `Pertinence : ${t.score}`,
      terms && `Termes correspondants : ${terms}`,
      t.source
    ].filter(Boolean).join(" · ");

    // only link to the official ATT&CK site
    const href = /^https:\/\/attack\.mitre\.org\//.test(t.url || "") ? t.url : null;
    const inner = `<b>${esc(t.technique_id)}</b> ${esc(name)}${tactics ? ` <em>${esc(tactics)}</em>` : ""}`;

    return href
      ? `<a class="tag" href="${esc(href)}" target="_blank" rel="noopener noreferrer" title="${esc(tip)}">${inner}</a>`
      : `<span class="tag" title="${esc(tip)}">${inner}</span>`;
  }).join("") || '<span class="muted">Aucune technique MITRE corrélée.</span>';

  const source = list[0]?.source;
  $("mitreSource").textContent = source
    ? `Source : ${source} · correspondance automatique par recherche dans le catalogue officiel (survol : tactique, pertinence, termes).`
    : "";
}

function showError(err) {
  const box = $("errorBox");
  box.classList.remove("hidden");
  box.textContent = "Impossible de charger les données : " + err.message;
  $("serviceBadge").textContent = "Service indisponible";
  $("serviceBadge").className = "status-chip danger";
}

let currentAnalysisId = null;

function setPdfState(label, disabled) {
  const btn = $("pdfBtn");
  btn.textContent = label;
  btn.disabled = disabled;
}

async function downloadReport() {
  if (!currentAnalysisId) return;
  setPdfState("Génération du PDF…", true);

  try {
    const r = await fetch(`${API}/api/risk/report.pdf?analysis_id=${encodeURIComponent(currentAnalysisId)}`);

    if (r.status === 410) {
      throw new Error("Analyse expirée (serveur redémarré) : cliquez sur Actualiser puis réessayez.");
    }
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);

    const blob = await r.blob();
    const name = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "")?.[1]
      || `lynx-rapport-${currentAnalysisId}.pdf`;

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (err) {
    console.error(err);
    const box = $("errorBox");
    box.classList.remove("hidden");
    box.textContent = "Impossible de générer le rapport : " + err.message;
  } finally {
    setPdfState("⤓ Rapport PDF", !currentAnalysisId);
  }
}

async function load() {
  $("errorBox").classList.add("hidden");
  $("serviceBadge").textContent = "Analyse en cours…";
  $("serviceBadge").className = "status-chip";
  $("lastUpdate").textContent = "Mise à jour " + new Date().toLocaleTimeString();

  try {
    const [risk, anomaly, investigation, scenario] = await Promise.all([
      get("/api/risk/analyze?normal_count=30"),
      get("/api/anomalies/demo"),
      get("/api/investigations/full-demo"),
      get("/api/events/attack-scenario")
    ]);

    currencySymbol = risk.currency?.symbol || "DT";
    currentAnalysisId = risk.analysis_id || null;
    setPdfState("⤓ Rapport PDF", !currentAnalysisId);

    const rows = risk.event_risks || [];
    const highest = [...rows].sort((a,b) =>
      (b.annual_loss_expectancy || 0) - (a.annual_loss_expectancy || 0)
    )[0];

    const report = investigation.sample_report;
    const techniques = report?.mitre_attack_mapping || [];
    const stages = report?.kill_chain?.stages_detected || [];
    const timeline = report?.timeline || [];
    const duration = report?.attack_summary?.time_span_minutes;

    $("serviceBadge").textContent = "AI Service opérationnel";
    $("serviceBadge").className = "status-chip success";

    $("kpiEvents").textContent = risk.summary?.total_events ?? rows.length;
    $("kpiAnomalies").textContent = anomaly.steps?.detection?.anomalies_detected ?? anomaly.detection?.anomalies_detected ?? "—";
    const detectionRate = anomaly.steps?.detection?.detection_rate || anomaly.detection?.detection_rate;
    $("anomalyRate").textContent = detectionRate ? `${detectionRate} classés anomalies` : "Détection ML";
    $("kpiAttacks").textContent = risk.summary?.attacks_found ?? 0;
    $("kpiReports").textContent = (risk.summary?.reports_generated ?? 0) + " rapport(s) généré(s)";
    $("kpiALE").textContent = money(highest?.annual_loss_expectancy);
    if (risk.currency && risk.currency.code !== "USD") {
      $("kpiALEnote").textContent =
        `Annual Loss Expectancy · 1 USD = ${Number(risk.currency.rate_from_usd).toFixed(4)} ${risk.currency.symbol}`;
    }

    $("riskPriority").textContent = highest?.priority || "—";
    $("riskProbability").textContent = pct(highest?.anomaly_probability);
    renderChi(risk.chi_square);
    $("riskStrategy").textContent = highest?.strategy || "—";
    $("riskVar95").textContent = money(highest?.value_at_risk_95);
    $("riskVar99").textContent = money(highest?.value_at_risk_99);

    renderBars(rows);
    renderRows(rows, risk.chi_square);
    renderKillChain(stages);

    $("chainSummary").textContent = stages.length + "/5 étapes observées";
    $("timelineNote").textContent = duration != null
      ? `Fenêtre observée : ${Number(duration).toFixed(0)} minute(s) · ${timeline.length} événement(s) dans le rapport.`
      : `${scenario.length || 0} événement(s) dans le scénario.`;

    $("reports").textContent = investigation.results?.reporting?.investigation_reports ?? 0;
    $("hypotheses").textContent = investigation.results?.reporting?.hypotheses_generated ?? 0;
    $("techniques").textContent = techniques.length;

    $("recommendation").innerHTML = highest
      ? `<strong>${esc(highest.priority || "Priorité")} — ${esc(highest.strategy || "Traitement à définir")}</strong>
         <br>Événement prioritaire : <strong>${esc(highest.event)}</strong>.
         Probabilité d’anomalie : ${pct(highest.anomaly_probability)}.
         Exposition annuelle estimée : ${money(highest.annual_loss_expectancy)}.`
      : "Aucune recommandation disponible.";

    renderControls(highest?.recommended_controls);
    renderIocs(report);
    renderTechniques(techniques);

    $("attackId").textContent = report?.attack_summary?.attack_id || "—";
    $("sourceIp").textContent = report?.attack_summary?.source_ip || "—";
    $("severity").textContent = report?.attack_summary?.severity || "—";
    $("confidence").textContent = pct(report?.attack_summary?.confidence);
    $("narrative").textContent = report?.kill_chain?.narrative || "Aucun récit d’investigation disponible.";
    $("affectedHosts").textContent = (report?.attack_summary?.affected_hosts || []).join(", ") || "—";
    $("affectedUsers").textContent = (report?.attack_summary?.affected_users || []).join(", ") || "—";
    $("timelineEvents").textContent = String(timeline.length);

    renderInvestigationTimeline(timeline);
  } catch (err) {
    console.error(err);
    showError(err);
  }
}

function formatTimestamp(value) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "medium" });
}

function renderInvestigationTimeline(timeline) {
  $("timelineList").innerHTML = (timeline?.length ? timeline : [])
    .map(t => {
      const actor = t.user && t.user !== "None" ? t.user : "—";
      const host = t.hostname || t.host || "—";
      const description = (t.description || `${t.event_type || "Événement"} · ${actor} · ${host}`)
        .replace(" by None", "");
      return `<div class="timeline-item">
        <span class="timeline-seq">#${t.sequence}</span>
        <div><strong>${esc(t.event_type)}</strong><small>${esc(formatTimestamp(t.timestamp))} · ${esc(description)}</small></div>
        <span class="priority ${priorityClass(t.severity)}">${esc(t.severity || "—")}</span>
      </div>`;
    }).join("") || '<div class="empty">Aucun événement dans la timeline.</div>';
}

$("refreshBtn").addEventListener("click", load);
$("pdfBtn").addEventListener("click", downloadReport);
load();