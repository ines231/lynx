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
    const [risk, anomaly, investigation] = await Promise.all([
      get("/api/risk/analyze?normal_count=30"),
      get("/api/anomalies/demo"),
      get("/api/investigations/full-demo")
    ]);

    const rows=risk.event_risks||[];
    const highest=[...rows].sort((a,b)=>(b.annual_loss_expectancy||0)-(a.annual_loss_expectancy||0))[0];
    $("kpiEvents").textContent=risk.summary?.total_events??rows.length;
    $("kpiAnomalies").textContent=anomaly.detection?.anomalies_detected??"—";
    $("anomalyRate").textContent=anomaly.detection?.detection_rate||"Détection ML";
    $("kpiAttacks").textContent=risk.summary?.attacks_found??0;
    $("kpiALE").textContent=money(highest?.annual_loss_expectancy);
    $("riskProbability").textContent=pct(highest?.anomaly_probability);
    $("riskVar95").textContent=money(highest?.value_at_risk_95);
    $("riskVar99").textContent=money(highest?.value_at_risk_99);
    $("riskPriority").textContent=highest?.priority||"—";
    renderBars(rows); renderRows(rows);
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