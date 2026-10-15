"use strict";
// Contas da interface (só admin): criar, mudar perfil, suspender, redefinir senha e app autenticador.

const { $, esc, api, toast, ROLE_LABEL } = J;
const state = { users: [], mfa: "todos", confirm: null, busy: false };

function situation(u) {
  if (!u.ativo) return ["suspensa", "Suspensa"];
  if (u.bloqueada) return ["bloqueada", "Bloqueada (tentativas erradas)"];
  if (u.senha_temporaria) return ["temporaria", "Aguardando primeiro login"];
  return ["ativa", "Ativa"];
}

function render() {
  $("rows").innerHTML = state.users.map(u => {
    const [cls, label] = situation(u);
    const confirming = state.confirm && state.confirm.id === u.id;
    let actions;
    if (confirming) {
      actions = `<span class="confirm-text">${esc(state.confirm.question)}</span>
        <button type="button" class="btn" data-act="cancel">Não</button>
        <button type="button" class="btn ${state.confirm.danger ? "danger solid" : "primary"}" data-act="confirm" ${state.busy ? "disabled" : ""}>Sim</button>`;
    } else if (u.voce) {
      actions = `<span class="num">sua conta</span>`;
    } else {
      actions = `<select class="role" data-role="${u.id}" aria-label="Perfil de ${esc(u.nome || u.email)}">
          ${Object.entries(ROLE_LABEL).map(([k, l]) => `<option value="${k}" ${u.perfil === k ? "selected" : ""}>${l}</option>`).join("")}
        </select>
        <button type="button" class="btn" data-act="reset-password" data-id="${u.id}">Nova senha</button>
        ${u.mfa ? `<button type="button" class="btn" data-act="reset-mfa" data-id="${u.id}">Redefinir app</button>` : ""}
        <button type="button" class="btn ${u.ativo ? "danger" : ""}" data-act="${u.ativo ? "disable" : "enable"}" data-id="${u.id}">${u.ativo ? "Suspender" : "Reativar"}</button>`;
    }
    return `<tr class="${u.ativo ? "" : "muted"}">
      <td class="client"><b>${esc(u.nome || "—")}</b></td>
      <td>${esc(u.email)}</td>
      <td>${esc(ROLE_LABEL[u.perfil] || u.perfil)}</td>
      <td><span class="state u-${cls}">${label}</span></td>
      <td>${u.mfa ? "Configurado" : `<span class="num">${state.mfa === "nenhum" ? "não exigido" : "no primeiro login"}</span>`}</td>
      <td class="num">${esc(u.ultimo_login || "nunca")}</td>
      <td><div class="actions">${actions}</div></td>
    </tr>`;
  }).join("");
}

function showSecret(person, password) {
  const card = $("secretCard");
  card.innerHTML = `<h2>Senha temporária de ${esc(person)}</h2>
    <p>Passe para a pessoa por um canal privado (Teams em conversa direta, pessoalmente). Ela aparece só agora.
    No primeiro login, a pessoa cria a senha dela${state.mfa === "nenhum" ? "" : " e configura o app autenticador"}.</p>
    <div class="secret-row"><code class="secret big" id="secretValue">${esc(password)}</code>
    <button type="button" class="btn" id="copySecret">Copiar</button></div>
    <p class="hint">Endereço para entrar: <b>${esc(location.origin)}</b></p>
    <button type="button" class="btn primary" id="closeSecret">Já passei, fechar</button>`;
  card.hidden = false;
  card.scrollIntoView({ behavior: "smooth", block: "center" });
}

async function load() {
  const data = await api("/api/users");
  state.users = data.usuarios; state.mfa = data.mfa;
  render();
}

async function run(promise, after) {
  state.busy = true; render();
  try {
    const data = await promise;
    if (data.senha_temporaria) showSecret(data.usuario.nome || data.usuario.email, data.senha_temporaria);
    toast(data.mensagem || "Feito.");
    if (after) after(data);
  } catch (error) { toast(error.message, true); }
  finally { state.busy = false; state.confirm = null; await load().catch(() => {}); }
}

const QUESTIONS = {
  "reset-password": u => [`Gerar nova senha temporária para ${u.nome || u.email}? A senha atual deixa de valer.`, false],
  "reset-mfa": u => [`Apagar o app autenticador de ${u.nome || u.email}? Ela configura de novo no próximo login.`, false],
  disable: u => [`Suspender ${u.nome || u.email}? A pessoa sai na hora.`, true],
  enable: u => [`Reativar ${u.nome || u.email}?`, false]
};

document.addEventListener("click", event => {
  const t = event.target.closest("button");
  if (!t) return;
  if (t.id === "newUser") { $("createForm").hidden = false; $("cName").focus(); return; }
  if (t.id === "cancelCreate") { $("createForm").hidden = true; $("createForm").reset(); return; }
  if (t.id === "closeSecret") { $("secretCard").hidden = true; $("secretCard").innerHTML = ""; return; }
  if (t.id === "copySecret") {
    const value = $("secretValue").textContent;
    navigator.clipboard.writeText(value).then(() => toast("Senha copiada."), () => {
      const range = document.createRange(); range.selectNodeContents($("secretValue"));
      const sel = getSelection(); sel.removeAllRanges(); sel.addRange(range);
      toast("Selecionei a senha: use Ctrl+C.");
    });
    return;
  }
  const act = t.dataset.act;
  if (!act) return;
  if (act === "cancel") { state.confirm = null; return render(); }
  if (act === "confirm") {
    const { id, action } = state.confirm;
    if (action === "disable" || action === "enable") return run(api(`/api/users/${id}`, { method: "POST", body: { ativo: action === "enable" } }));
    return run(api(`/api/users/${id}/${action}`, { method: "POST" }));
  }
  const user = state.users.find(u => u.id === +t.dataset.id);
  if (user && QUESTIONS[act]) {
    const [question, danger] = QUESTIONS[act](user);
    state.confirm = { id: user.id, action: act, question, danger };
    render();
  }
});

document.addEventListener("change", event => {
  const select = event.target.closest("select[data-role]");
  if (!select) return;
  run(api(`/api/users/${select.dataset.role}`, { method: "POST", body: { perfil: select.value } }));
});

$("createForm").addEventListener("submit", event => {
  event.preventDefault();
  const body = { nome: $("cName").value.trim(), email: $("cEmail").value.trim(), perfil: $("cRole").value };
  run(api("/api/users", { method: "POST", body }), () => { $("createForm").reset(); $("createForm").hidden = true; });
});

J.loadMe().then(load).catch(error => { $("banner").textContent = `Não foi possível carregar: ${error.message}`; $("banner").hidden = false; });
