// Utilitários das páginas que imitam o frontend do Zabbix (renderizadas "no servidor", sem SPA).
const pad = n => String(n).padStart(2, '0');
const now = new Date();
const ago = min => new Date(now.getTime() - min * 60e3);
const sameDay = (a, b) => a.toDateString() === b.toDateString();
// Como o Zabbix: só a hora para eventos de hoje; data completa para os anteriores.
const zbxTime = d => (sameDay(d, now) ? '' : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} `) +
  `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
// Como no Zabbix real, o ícone de seta tem tamanho definido por CSS (sem isso o link fica invisível).
document.write('<style>.arrow-right { display: inline-block; width: 12px; height: 12px; background: #888; }</style>');
const badge = (cls, text) => `<span class="${cls}">${text}</span>`;

function writeTable(headersHtml, rows, { perPage = 50 } = {}) {
  const page = Number(new URLSearchParams(location.search).get('page') || 1);
  const pages = Math.max(1, Math.ceil(rows.length / perPage));
  const slice = rows.slice((page - 1) * perPage, page * perPage);
  let paging = '';
  if (pages > 1) {
    const link = p => `${location.pathname}?page=${p}`;
    paging = '<div class="table-paging"><nav>' +
      Array.from({ length: pages }, (_, i) => `<a href="${link(i + 1)}">${i + 1}</a>`).join('') +
      (page < pages ? `<a href="${link(page + 1)}"><span class="arrow-right"></span></a>` : '') + '</nav></div>';
  }
  document.write(`<table class="list-table"><thead><tr>${headersHtml}</tr></thead><tbody>${slice.join('')}</tbody></table>${paging}`);
}
