"use strict";
// Revisão dos relatórios mensais. Dados de /api; ações enviam o token da sessão (X-CSRF-Token).

const ICON = {
  pdf: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M14 3v6h6"/></svg>',
  ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" aria-hidden="true"><path d="M5 12l5 5 9-10"/></svg>',
  redo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M20 11a8 8 0 10-2.3 5.7M20 4v7h-7"/></svg>'
};
const RESULT_LABEL = { sucesso: "Completo", parcial: "Com limitações", falha: "Sem dados" };
const STATE_LABEL = { pendente: "Pendente", aprovado: "Aprovado", rejeitado: "Rejeitado", falha: "Falha" };
const MONTHS = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"];
const FILTERS = [["pendente", "Pendentes"], ["parcial", "Com limitações"], ["falha", "Falhas"], ["aprovado", "Aprovados"], ["rejeitado", "Rejeitados"], ["todos", "Todos"]];
const COUNT_LABEL = { maquinas: "máquinas", alertas: "alertas", atividades: "atividades", dispositivos: "dispositivos", hosts: "hosts", problemas: "problemas", disponibilidade: "indicadores" };

const state = {
  me: null, month: null, reports: [], jobs: [], filter: "pendente", query: "",
  selected: new Set(), openId: null, detail: null, rejecting: false, confirmBulk: false, busy: false
};
const { $, esc, api, toast } = J;
const monthLabel = m => m ? `${MONTHS[+m.slice(5, 7) - 1]}/${m.slice(0, 4)}` : "";
const canReview = () => state.me && (state.me.perfil === "revisor" || state.me.perfil === "admin");
const isAdmin = () => state.me && state.me.perfil === "admin";

// --- carga ------------------------------------------------------------------------------

async function start() {
  try {
    state.me = await J.loadMe();
    const overview = await api("/api/overview");
    $("nextClose").textContent = overview.proximo_fechamento ? `Próximo fechamento: ${overview.proximo_fechamento}` : "";
    const months = overview.competencias;
    $("competencia").innerHTML = months.map(m => `<option value="${esc(m)}">${esc(monthLabel(m))}</option>`).join("");
    if (!months.length) {
      $("subtitle").textContent = "Nenhum relatório gerado ainda.";
      $("empty").textContent = overview.proximo_fechamento
        ? `O primeiro fechamento roda em ${overview.proximo_fechamento}. Os relatórios aparecem aqui para revisão.`
        : "Os relatórios aparecem aqui depois do primeiro fechamento mensal.";
      $("empty").hidden = false;
      return;
    }
    state.month = months[0];
    await loadReports();
  } catch (error) {
    $("banner").textContent = `Não foi possível carregar: ${error.message}`;
    $("banner").hidden = false;
  }
}

async function loadReports() {
  const data = await api(`/api/reviews?month=${encodeURIComponent(state.month)}`);
  state.reports = data.relatorios;
  state.jobs = data.jobs;
  const ids = new Set(state.reports.filter(r => r.situacao === "pendente").map(r => r.id));
  state.selected.forEach(id => { if (!ids.has(id)) state.selected.delete(id); });
  render();
  watchJobs();
}

let jobTimer = null;
function watchJobs() {
  const active = state.jobs.some(j => j.status === "na_fila" || j.status === "gerando");
  if (active && !jobTimer) jobTimer = setInterval(pollJobs, 5000);
  if (!active && jobTimer) { clearInterval(jobTimer); jobTimer = null; }
}

async function pollJobs() {
  try {
    const before = new Set(state.jobs.filter(j => j.status === "na_fila" || j.status === "gerando").map(j => j.id));
    const data = await api("/api/jobs");
    state.jobs = data.jobs;
    const finished = state.jobs.filter(j => before.has(j.id) && (j.status === "concluido" || j.status === "falha"));
    finished.forEach(j => toast(`${j.customer}: ${j.message}`, j.status === "falha"));
    if (finished.length) await loadReports(); else { renderJobs(); watchJobs(); }
  } catch (error) { /* tenta de novo no próximo ciclo */ }
}

// --- desenho ------------------------------------------------------------------------------

function matches(r) {
  const f = state.filter;
  const byFilter = f === "todos" || (f === "parcial" ? r.resultado === "parcial" && r.situacao === "pendente" : r.situacao === f);
  return byFilter && (!state.query || r.cliente.toLowerCase().includes(state.query));
}

function render() {
  const count = s => state.reports.filter(r => r.situacao === s).length;
  const pending = count("pendente");
  $("navCount").textContent = pending; $("navCount").hidden = pending === 0;
  $("subtitle").textContent = `Fechamento de ${monthLabel(state.month)} · ${state.reports.length} cliente(s)`;
  $("competencia").value = state.month;

  const tiles = [["pendente", pending, "aguardando revisão"], ["aprovado", count("aprovado"), "aprovados para envio"],
                 ["rejeitado", count("rejeitado"), "rejeitados"], ["falha", count("falha"), "sem dados (falha na coleta)"]];
  $("summary").innerHTML = tiles.map(([k, n, l]) =>
    `<button type="button" class="tile t-${k}" data-f="${k}" aria-pressed="${state.filter === k}"><span class="n">${n}</span><span class="l">${l}</span></button>`).join("");
  $("chips").innerHTML = FILTERS.map(([k, l]) => `<button type="button" class="chip" data-f="${k}" aria-pressed="${state.filter === k}">${l}</button>`).join("");

  const rows = state.reports.filter(matches);
  $("empty").textContent = "Nenhum relatório com esse filtro.";
  $("empty").hidden = rows.length > 0;
  const review = canReview();
  $("rows").innerHTML = rows.map(r => {
    const pending = r.situacao === "pendente";
    const reviewed = r.situacao === "aprovado" || r.situacao === "rejeitado";
    const stateCell = `<span class="state ${r.situacao}">${STATE_LABEL[r.situacao] || r.situacao}` +
      (reviewed ? `<small>${esc(r.revisado_por || "")}</small>` : "") + "</span>";
    let actions = "";
    if (r.situacao === "falha") {
      actions = isAdmin() ? `<button type="button" class="btn" data-act="redo" data-id="${r.id}">${ICON.redo}Gerar de novo</button>` : "";
    } else {
      actions = `<button type="button" class="btn" data-act="open" data-id="${r.id}">${ICON.pdf}Abrir</button>` +
        (pending && review ? `<button type="button" class="btn ok" data-act="approve" data-id="${r.id}">${ICON.ok}Aprovar</button>` : "");
    }
    const plats = r.plataformas.length
      ? r.plataformas.map(p => `<span class="plat ${esc(p.status)}">${esc(p.plataforma)}</span>`).join("")
      : `<span class="num">—</span>`;
    return `<tr data-id="${r.id}" class="${state.selected.has(r.id) ? "sel" : ""}">
      <td class="check">${pending && review ? `<input type="checkbox" data-sel="${r.id}" ${state.selected.has(r.id) ? "checked" : ""} aria-label="Selecionar ${esc(r.cliente)}">` : ""}</td>
      <td class="client"><b>${esc(r.cliente)}</b><small>#${r.id}</small></td>
      <td><div class="plats">${plats}</div></td>
      <td><span class="pill ${esc(r.resultado)}">${RESULT_LABEL[r.resultado] || esc(r.resultado)}</span></td>
      <td>${stateCell}</td>
      <td class="num">${esc(r.gerado_em || "")}</td>
      <td><div class="actions">${actions}</div></td>
    </tr>`;
  }).join("");

  const visiblePending = rows.filter(r => r.situacao === "pendente");
  $("checkAll").hidden = !review;
  $("checkAll").disabled = visiblePending.length === 0;
  $("checkAll").checked = visiblePending.length > 0 && visiblePending.every(r => state.selected.has(r.id));
  renderJobs();
  renderBulk();
  renderDrawer();
}

function renderJobs() {
  const recent = state.jobs.slice(0, 5);
  $("jobs").hidden = recent.length === 0;
  const label = { na_fila: "Na fila", gerando: "Gerando…", concluido: "Concluído", falha: "Falhou" };
  $("jobs").innerHTML = `<h2>Gerações pedidas nesta sessão do servidor</h2>` + recent.map(j =>
    `<div class="job"><span class="st ${esc(j.status)}">${label[j.status] || esc(j.status)}</span>
     <span>${esc(j.customer)} · ${esc(monthLabel(j.competencia))}</span>
     <small>${esc(j.message || `pedido por ${j.requested_by}`)}</small></div>`).join("");
}

function renderBulk() {
  const n = state.selected.size;
  $("bulk").hidden = n === 0;
  if (!n) { state.confirmBulk = false; return; }
  const plural = n === 1 ? "relatório" : "relatórios";
  $("bulk").innerHTML = state.confirmBulk
    ? `<span>Aprovar <strong>${n}</strong> ${plural} de ${esc(monthLabel(state.month))}? Fica registrado que ${esc(state.me.nome)} aprovou.</span><span class="spacer"></span>
       <button type="button" class="btn" data-bulk="cancel">Cancelar</button>
       <button type="button" class="btn ok" data-bulk="confirm" ${state.busy ? "disabled" : ""}>${ICON.ok}Confirmar aprovação</button>`
    : `<span><strong>${n}</strong> ${n === 1 ? "selecionado" : "selecionados"}</span><span class="spacer"></span>
       <button type="button" class="btn" data-bulk="clear">Limpar seleção</button>
       <button type="button" class="btn ok" data-bulk="ask">${ICON.ok}Aprovar selecionados</button>`;
}

function countsText(counts) {
  return Object.entries(counts || {}).map(([k, v]) => `${v} ${COUNT_LABEL[k] || k}`).join(", ");
}

function renderDrawer() {
  const d = $("drawer");
  const r = state.reports.find(x => x.id === state.openId);
  d.hidden = $("scrim").hidden = !r;
  if (!r) return;
  const detail = state.detail && state.detail.id === r.id ? state.detail : null;
  const reviewed = r.situacao === "aprovado" || r.situacao === "rejeitado";
  let body = "";
  if (r.situacao === "falha") body += `<div class="note bad"><strong>Relatório não gerado.</strong> ${esc(r.observacao || "")}</div>`;
  if (r.resultado === "parcial" && r.situacao === "pendente") body += `<div class="note">Uma plataforma falhou na coleta e ficou fora do relatório. Confira antes de aprovar.</div>`;
  if (!detail) {
    body += `<p class="loading">Carregando detalhes…</p>`;
  } else {
    if (detail.plataformas.length) {
      body += `<section><h3>Plataformas</h3><div class="plist">` + detail.plataformas.map(p => `<div>
        <div class="top"><span class="name">${esc(p.plataforma)}</span><span class="info">${esc(countsText(p.contagens))}</span>
        <span class="st"><span class="pill ${esc(p.status)}">${p.status === "sucesso" ? "Coletado" : p.status === "parcial" ? "Parcial" : "Falhou"}</span></span></div>
        ${(p.erros || []).length || (p.avisos || []).length ? `<ul>${(p.erros || []).map(e => `<li class="err">${esc(e)}</li>`).join("")}${(p.avisos || []).map(a => `<li>${esc(a)}</li>`).join("")}</ul>` : ""}
      </div>`).join("") + `</div></section>`;
    }
    if (detail.arquivos.length) {
      body += `<section><h3>Arquivos</h3><div class="files">` + detail.arquivos.map(f => {
        const ext = f.nome.split(".").pop();
        return `<div class="file"><span class="ext ${esc(ext)}">${esc(ext.toUpperCase())}</span>
          <span class="fname">${esc(f.titulo)}<small>${esc(f.descricao)}</small></span>${f.vai_ao_cliente ? `<span class="send">vai ao cliente</span>` : ""}
          <a class="btn" href="/files/${r.id}/${encodeURIComponent(f.nome)}" target="_blank" rel="noopener">${ext === "pdf" ? "Abrir" : "Baixar"}</a></div>`;
      }).join("") + `</div></section>`;
    }
  }
  body += `<section><h3>Registro</h3><dl class="facts">
    <dt>Gerado</dt><dd>${esc(r.gerado_em || "—")}, ${r.origem && r.origem.startsWith("agendamento") ? "pelo fechamento automático" : `por ${esc(r.gerado_por || "—")}`}</dd>
    ${reviewed ? `<dt>${r.situacao === "aprovado" ? "Aprovado" : "Rejeitado"}</dt><dd>${esc(r.revisado_em || "")}, por ${esc(r.revisado_por || "—")}</dd>` : ""}
    ${reviewed && r.observacao ? `<dt>${r.situacao === "rejeitado" ? "Motivo" : "Observação"}</dt><dd>${esc(r.observacao)}</dd>` : ""}
    ${r.situacao === "pendente" && r.observacao ? `<dt>Problemas</dt><dd>${esc(r.observacao)}</dd>` : ""}
  </dl></section>`;
  const typed = { approveNote: $("approveNote")?.value, reason: $("reason")?.value };  // a atualização não apaga o que foi digitado
  d.innerHTML = `<header><div><h2 id="dTitle">${esc(r.cliente)}</h2>
      <p>${esc(monthLabel(r.competencia) || r.periodo)} · revisão #${r.id} · <span class="pill ${esc(r.resultado)}">${RESULT_LABEL[r.resultado] || esc(r.resultado)}</span></p></div>
      <button type="button" class="x" data-close aria-label="Fechar">×</button></header>
    <div class="body">${body}</div>${footer(r)}`;
  for (const [id, value] of Object.entries(typed)) if (value && $(id)) $(id).value = value;
}

function footer(r) {
  const redo = label => isAdmin() ? `<button type="button" class="btn primary" data-act="redo" data-id="${r.id}">${ICON.redo}${label}</button>` : "";
  if (r.situacao === "falha") return isAdmin() ? `<footer><div class="row">${redo("Gerar de novo")}</div></footer>` : "";
  if (r.situacao === "rejeitado") return isAdmin() ? `<footer><div class="row">${redo("Gerar de novo depois de corrigir")}
      <button type="button" class="btn" data-act="reopen" data-id="${r.id}">Voltar para pendente</button></div></footer>` : "";
  if (r.situacao === "aprovado") return isAdmin() ? `<footer><div class="row"><button type="button" class="btn" data-act="reopen" data-id="${r.id}">Voltar para pendente</button></div></footer>` : "";
  if (!canReview()) return `<footer><p class="hint">Seu perfil é de leitura: a aprovação é feita por um revisor.</p></footer>`;
  if (state.rejecting) return `<footer>
      <label class="field-label" for="reason">Motivo da rejeição (obrigatório)</label>
      <textarea id="reason" maxlength="1000" placeholder="Ex.: faltou o Zabbix, hosts novos ainda sem grupo"></textarea>
      <span class="err" id="reasonErr" hidden>Escreva o motivo para registrar a rejeição.</span>
      <div class="row"><button type="button" class="btn" data-act="cancelReject">Cancelar</button>
      <button type="button" class="btn danger solid" data-act="reject" data-id="${r.id}" ${state.busy ? "disabled" : ""}>Rejeitar relatório</button></div></footer>`;
  return `<footer>
    <label class="field-label" for="approveNote">Observação (opcional)</label>
    <textarea id="approveNote" maxlength="1000" placeholder="Ex.: conferido com o técnico da conta"></textarea>
    <div class="row"><button type="button" class="btn danger" data-act="askReject">Rejeitar</button>
    ${isAdmin() ? redo("Gerar de novo") : ""}
    <button type="button" class="btn ok" data-act="approve" data-id="${r.id}" ${state.busy ? "disabled" : ""}>${ICON.ok}Aprovar</button></div></footer>`;
}

async function openDetail(id) {
  state.openId = id; state.rejecting = false; state.detail = null;
  render();
  try { state.detail = await api(`/api/reviews/${id}`); } catch (error) { toast(error.message, true); }
  if (state.openId === id) renderDrawer();
}

async function act(promise, after) {
  state.busy = true; render();
  try { const data = await promise; toast(data.mensagem || "Feito."); if (after) after(data); await loadReports(); }
  catch (error) { toast(error.message, true); }
  finally { state.busy = false; render(); }
}

// --- eventos ------------------------------------------------------------------------------

document.addEventListener("click", event => {
  const t = event.target.closest("button, input, tr, a, .scrim");
  if (!t || t.tagName === "A") return;
  if (t.id === "scrim" || t.hasAttribute("data-close")) { state.openId = null; state.rejecting = false; return render(); }
  if (t.dataset.f) { state.filter = t.dataset.f; return render(); }
  if (t.dataset.sel) { const id = +t.dataset.sel; t.checked ? state.selected.add(id) : state.selected.delete(id); state.confirmBulk = false; return render(); }
  if (t.id === "checkAll") {
    state.reports.filter(matches).filter(r => r.situacao === "pendente").forEach(r => t.checked ? state.selected.add(r.id) : state.selected.delete(r.id));
    state.confirmBulk = false; return render();
  }
  if (t.dataset.bulk) {
    const a = t.dataset.bulk;
    if (a === "clear") state.selected.clear();
    if (a === "ask") state.confirmBulk = true;
    if (a === "cancel") state.confirmBulk = false;
    if (a === "confirm") {
      const ids = [...state.selected];
      return act(api("/api/reviews/approve", { method: "POST", body: { ids } }), () => { state.selected.clear(); state.confirmBulk = false; });
    }
    return render();
  }
  if (t.dataset.act) {
    const id = +t.dataset.id, a = t.dataset.act;
    if (a === "open") return openDetail(id);
    if (a === "approve") {
      const note = state.openId === id && $("approveNote") ? $("approveNote").value : "";
      return act(api(`/api/reviews/${id}/approve`, { method: "POST", body: { nota: note } }), () => state.selected.delete(id));
    }
    if (a === "askReject") { state.rejecting = true; renderDrawer(); if ($("reason")) $("reason").focus(); return; }
    if (a === "cancelReject") { state.rejecting = false; return renderDrawer(); }
    if (a === "reject") {
      const reason = $("reason") ? $("reason").value.trim() : "";
      if (!reason) { $("reasonErr").hidden = false; $("reason").focus(); return; }
      return act(api(`/api/reviews/${id}/reject`, { method: "POST", body: { motivo: reason } }), () => { state.rejecting = false; });
    }
    if (a === "reopen") return act(api(`/api/reviews/${id}/reopen`, { method: "POST" }));
    if (a === "redo") return act(api(`/api/reviews/${id}/regenerate`, { method: "POST" }));
  }
  if (t.tagName === "TR" && t.dataset.id) return openDetail(+t.dataset.id);
});
document.addEventListener("keydown", e => { if (e.key === "Escape" && state.openId) { state.openId = null; state.rejecting = false; render(); } });
$("q").addEventListener("input", e => { state.query = e.target.value.trim().toLowerCase(); render(); });
$("competencia").addEventListener("change", e => {
  state.month = e.target.value; state.selected.clear(); state.openId = null;
  loadReports().catch(error => toast(error.message, true));
});
start();
