// Renderiza uma tabela paginada no estilo SPA: carrega com atraso, mostra spinner ao trocar de página.
function renderTable({ headers, rows, pageSize = 10, delay = 300, nextLabel = 'Próxima página' }) {
  const app = document.getElementById('app');
  const spinner = '<div class="spinner" role="progressbar">Carregando...</div>';
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  let page = 0;
  const draw = () => {
    const slice = rows.slice(page * pageSize, (page + 1) * pageSize);
    app.innerHTML =
      `<table><thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>` +
      `<tbody>${slice.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>` +
      (rows.length > pageSize ? `<button aria-label="${nextLabel}" ${page >= pages - 1 ? 'disabled' : ''}>›</button>` : '');
    const next = app.querySelector('button');
    if (next) next.onclick = () => { app.innerHTML = spinner; page++; setTimeout(draw, 200); };
  };
  app.innerHTML = spinner;
  setTimeout(draw, delay);
}
