import { init, scan } from "./engine.js";

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const pct = (x) => `${Math.round(x * 100)}%`;

let ready = false;

function render(r) {
  const rows = r.findings.length
    ? r.findings.map((f) => `<tr><td class="sev ${esc(f.severity)}">${esc(f.severity)}</td>
        <td class="rule">${esc(f.rule)}</td><td>${esc(f.detail)}</td></tr>`).join("")
    : `<tr><td colspan="3">No rule triggered.</td></tr>`;
  const path = r.decision_path.map((s) => `<li>${esc(s)}</li>`).join("");
  const feats = Object.entries(r.features).filter(([, v]) => v !== 0 && v !== -1)
    .map(([k, v]) => `<div>${esc(k)} = ${esc(v)}</div>`).join("");

  return `
    <div class="verdict ${r.verdict}">${r.verdict}</div>
    <div class="url">${esc(r.url)}</div>
    <div class="bar"><div style="width:${Math.round(r.risk * 100)}%"></div></div>
    <div class="nums">
      <span>risk <b>${pct(r.risk)}</b></span>
      <span>decision tree <b>${pct(r.tree_probability)}</b></span>
      <span>rules <b>${pct(r.heuristic_score)}</b></span>
      <span>known domain <b>${r.trusted_domain ? "yes" : "no"}</b></span>
    </div>
    <div class="wrap"><table>
      <tr><th>severity</th><th>rule</th><th>detail</th></tr>${rows}
    </table></div>
    <details><summary>Decision path in the tree (${r.decision_path.length} steps)</summary><ol class="path">${path}</ol></details>
    <details><summary>Features extracted from the URL</summary><div class="feats">${feats || "all zero"}</div></details>`;
}

function runSingle(url) {
  url = url.trim();
  if (!url || !ready) return;
  const box = $("#result");
  box.innerHTML = render(scan(url));
  box.hidden = false;
  const u = new URL(location.href);
  u.searchParams.set("url", url);
  history.replaceState(null, "", u);
}

function runBatch() {
  const urls = $("#batch").value.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).slice(0, 500);
  if (!urls.length || !ready) return;
  const results = urls.map((u) => scan(u));
  const count = (v) => results.filter((r) => r.verdict === v).length;
  $("#batch-result").innerHTML = `
    <p class="note">${results.length} URLs: <span class="PHISHING">${count("PHISHING")} phishing</span>,
      <span class="SUSPICIOUS">${count("SUSPICIOUS")} suspicious</span>, <span class="CLEAN">${count("CLEAN")} clean</span></p>
    <table class="batch">
      <tr><th>verdict</th><th>risk</th><th>url</th><th>main finding</th></tr>
      ${results.map((r) => `<tr><td class="${r.verdict}"><b>${r.verdict}</b></td><td>${pct(r.risk)}</td>
        <td class="url-cell">${esc(r.url)}</td><td>${esc(r.findings[0]?.rule ?? "")}</td></tr>`).join("")}
    </table>`;
}

function selectTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  $("#tab-single").hidden = name !== "single";
  $("#tab-batch").hidden = name !== "batch";
}

$("#form").addEventListener("submit", (e) => { e.preventDefault(); runSingle($("#url").value); });
document.querySelectorAll(".examples button").forEach((b) => b.addEventListener("click", () => {
  $("#url").value = b.dataset.url;
  runSingle(b.dataset.url);
}));
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));
$("#batch-run").addEventListener("click", runBatch);
$("#batch").value = [
  "google.com",
  "https://github.com/RedaKarrach/URLPhishingDetector",
  "hxxp://192.168.12[.]7/banque/connexion.php",
  "hxxps://login.microsoftonline.com.verify-session[.]top/common/oauth2",
  "hxxp://secure-update-cihbank[.]online/client/index.php",
  "hxxps://drive-docs.000webhostapp[.]com/invoice.pdf.exe",
].join("\n");

fetch("model.json")
  .then((r) => r.json())
  .then((model) => {
    init(model);
    ready = true;
    const q = new URLSearchParams(location.search).get("url");
    if (q) { $("#url").value = q; runSingle(q); }
  })
  .catch(() => { $("#result").hidden = false; $("#result").textContent = "Could not load the model (model.json)."; });
