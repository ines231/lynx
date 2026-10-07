const API = window.location.origin;
const $ = id => document.getElementById(id);
const money = v => typeof v === "number" ? "$" + v.toLocaleString(undefined,{maximumFractionDigits:0}) : (v ?? "—");
const pct = v => typeof v === "number" ? (v*100).toFixed(1)+"%" : (v ?? "—");

async function get(path){
  const r=await fetch(API+path);
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}

function priorityClass(p){
  const x=(p||"").toLowerCase();
  return x.includes("high")||x.includes("critical")?"high":x.includes("medium")?"medium":"low";
}

function renderRows(rows){
  const body=$("riskTable");
  if(!rows?.length){body.innerHTML='<tr><td colspan="6" class="empty">Aucun événement retourné.</td></tr>';return;}
  body.innerHTML=rows.map(x=>`<tr>
    <td><strong>${x.event||"Unknown"}</strong></td>
    <td>${x.user||"demo"}</td>
    <td>${pct(x.anomaly_probability)}</td>
    <td>${money(x.annual_loss_expectancy)}</td>
    <td><span class="priority ${priorityClass(x.priority)}">${x.priority||"—"}</span></td>
    <td>${x.strategy||"—"}</td>
  </tr>`).join("");
}

function renderBars(rows){
  const top=[...(rows||[])].sort((a,b)=>(b.anomaly_probability||0)-(a.anomaly_probability||0)).slice(0,5);
  $("riskBars").innerHTML=top.map(x=>`<div class="bar-row"><span>${x.event||"Event"}</span><div class="bar"><i style="width:${Math.min(100,(x.anomaly_probability||0)*100)}%"></i></div><b>${pct(x.anomaly_probability)}</b></div>`).join("");
}

async function load(){
  $("lastUpdate").textContent="Mise à jour "+new Date().toLocaleTimeString();
  try{
    const [risk, investigation] = await Promise.all([
      get("/api/risk/analyze?normal_count=30"),
      get("/api/investigations/full-demo")
    ]);

    const rows=risk.event_risks||[];
    const highest=[...rows].sort((a,b)=>(b.annual_loss_expectancy||0)-(a.annual_loss_expectancy||0))[0];
    $("kpiEvents").textContent=risk.summary?.total_events??rows.length;
    const detection=investigation.results?.detection||{};
    $("kpiAnomalies").textContent=detection.anomalies??"—";
    $("anomalyRate").textContent=detection.total_events ? ((detection.anomalies/detection.total_events)*100).toFixed(1)+"% détectés par Isolation Forest" : "Détection ML";
    $("kpiAttacks").textContent=risk.summary?.attacks_found??0;
    $("kpiALE").textContent=money(highest?.annual_loss_expectancy);
    $("riskProbability").textContent=pct(highest?.anomaly_probability);
    $("riskVar95").textContent=money(highest?.value_at_risk_95);
    $("riskVar99").textContent=money(highest?.value_at_risk_99);
    $("riskPriority").textContent=highest?.priority||"—";
    renderBars(rows); renderRows(rows);
    const report=investigation.sample_report;
    if(report){
      const s=report.attack_summary||{};
      $("reportId").textContent=s.attack_id||report.report_id||"—";
      $("reportSource").textContent=s.source_ip||"—";
      $("reportConfidence").textContent=typeof s.confidence==="number" ? (s.confidence*100).toFixed(1)+"%" : "—";
      $("reportMitre").textContent=(report.mitre_attack_mapping||[]).length;
      $("reportStatus").textContent=s.status||"—";
      $("reportNarrative").textContent=report.kill_chain?.narrative||"Aucune synthèse disponible.";
      const iocs=report.indicators_of_compromise||{};
      const values=[...(iocs.ips||[]),...(iocs.domains||[]),...(iocs.file_hashes||[]),...(iocs.process_names||[])].slice(0,12);
      $("reportIocs").innerHTML=values.length ? values.map(()=>"<span class=\\"chip\\"></span>").join("") : "<span class=\\"empty\\">Aucun IOC extrait.</span>";
      values.forEach((v,i)=>{const el=$("reportIocs").children[i]; if(el) el.textContent=v;});
      $("reportNextSteps").innerHTML=(report.next_steps||[]).slice(0,5).map(()=>"<li></li>").join("");
      (report.next_steps||[]).slice(0,5).forEach((v,i)=>{const el=$("reportNextSteps").children[i]; if(el) el.textContent=v;});
      const detected=new Set(report.kill_chain?.stages_detected||[]);
      document.querySelectorAll(".stage").forEach(el=>el.classList.toggle("detected",detected.has(el.dataset.stage)));
    }
    $("reports").textContent=investigation.results?.reporting?.investigation_reports??risk.summary?.reports_generated??0;
    $("hypotheses").textContent=investigation.results?.reporting?.hypotheses_generated??risk.summary?.hypotheses_generated??0;
    $("recommendation").innerHTML=highest
      ? `<strong>${highest.priority||"Priorité"} — ${highest.strategy||"Traitement à définir"}</strong><br>Le moteur recommande de traiter en priorité l’événement <strong>${highest.event||"à risque"}</strong>, avec une probabilité d’anomalie de ${pct(highest.anomaly_probability)} et une exposition annuelle estimée à ${money(highest.annual_loss_expectancy)}.`
      : "Aucune recommandation disponible.";
  }catch(e){
    console.error(e);
    $("recommendation").innerHTML='<strong>Service indisponible.</strong><br>Vérifie que FastAPI est lancé puis actualise le dashboard.';
  }
}
$("refreshBtn").addEventListener("click",load);
load();