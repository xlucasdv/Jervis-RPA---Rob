"use strict";
// Peças comuns às páginas: chamadas à API com o token da sessão, avisos e dados de quem está logado.

const J = (() => {
  const ROLE_LABEL = { leitura: "Leitura", revisor: "Revisor", admin: "Administrador" };
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const self = { me: null, ROLE_LABEL, $, esc };

  self.api = async (path, options = {}) => {
    const init = { method: options.method || "GET", headers: { Accept: "application/json" }, credentials: "same-origin" };
    if (init.method !== "GET") {
      init.headers["Content-Type"] = "application/json";
      init.headers["X-CSRF-Token"] = self.me ? self.me.csrf : "";
      init.body = JSON.stringify(options.body || {});
    }
    const response = await fetch(path, init);
    if (response.status === 401) { location.href = "/login"; throw new Error("Sessão expirada."); }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.erro || `Erro ${response.status}`);
    return data;
  };

  let toastTimer;
  self.toast = (message, bad = false) => {
    const t = $("toast");
    t.textContent = message; t.className = bad ? "toast bad" : "toast"; t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, bad ? 7000 : 4000);
  };

  // Quem está logado: nome e perfil na barra lateral, link de Usuários só para admin
  self.loadMe = async () => {
    self.me = await self.api("/api/me");
    $("userName").textContent = self.me.nome;
    $("userRole").textContent = ROLE_LABEL[self.me.perfil] || self.me.perfil;
    const users = $("navUsers");
    if (users) users.hidden = self.me.perfil !== "admin";
    return self.me;
  };

  document.addEventListener("click", event => {
    if (!event.target.closest("#logout")) return;
    fetch("/logout", { method: "POST", headers: { "X-CSRF-Token": self.me ? self.me.csrf : "" }, credentials: "same-origin" })
      .finally(() => { location.href = "/saiu"; });
  });
  return self;
})();
