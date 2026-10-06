# Plataformas e dados coletados

O que é coletado de cada plataforma, como os dados são padronizados e classificados e o que os relatórios
mostram. Ajustes de páginas, colunas e limites: [Configuração](configuracao.md#ajustes-da-coleta-params).

Os endereços das páginas e os rótulos de colunas padrão são um ponto de partida e **precisam ser validados em
cada ambiente real** com `jervis check` (versão do Zabbix, datacenter da Acronis, idioma do perfil do usuário).

## Sophos Central

`jervis collect` autentica, percorre as páginas configuradas e grava
`output/<data-hora>/<plataforma>.json`:

```json
{
  "platform": "sophos", "status": "parcial", "counts": {"dispositivos": 27, "alertas": 3},
  "issues": [{"stage": "alertas/incidente", "category": "interface_alterada", "severity": "erro",
              "message": "Coluna(s) obrigatória(s) não encontrada(s): tipo, data_hora. Colunas na página: ...",
              "url": "...", "screenshot": null, "timestamp": "2026-10-06T10:45:18-03:00"}],
  "datasets": {
    "dispositivos": [{"nome": "SRV-FS01", "sistema_operacional": "Windows Server 2019", "status_agente": "Bad",
                      "ultima_comunicacao": "Sep 30, 2026 4:40 PM", "situacao_protecao": "Not protected",
                      "ip": null, "ultimo_usuario": null, "grupo": null, "origem": "servidor"}],
    "alertas": [{"tipo": "Malware detected: Troj/Agent-XYZ", "severidade": "alta", "dispositivo": "PC-003",
                 "data_hora": "Oct 6, 2026 8:01 AM", "situacao": "Open", "descricao": "...", "origem": "alerta"}]
  }
}
```

| Feature | Implementação |
|---|---|
| 2.1 Navegação | Cada conjunto declara páginas (`origem → caminho`), abertas a partir da URL pós-login. Padrão: computadores, servidores e alertas. Espera o carregamento da SPA (spinner, renderização tardia) e percorre a paginação |
| 2.2 Dispositivos e agentes | `nome`, `sistema_operacional`, `status_agente`, `ultima_comunicacao`, `situacao_protecao` (+ `ip`, `ultimo_usuario`, `grupo` quando houver) e `origem` (computador/servidor) |
| 2.3 Alertas e incidentes | `tipo`, `severidade` (padronizada: critica/alta/media/baixa/informativa, inclusive quando exibida como ícone), `dispositivo`, `data_hora`, `situacao`. Outras páginas (ex.: casos de ameaça) entram como novas origens do conjunto `alertas` |
| 2.4 Tratamento de falhas | Cada página é coletada isoladamente: uma falha não impede as demais, e o resultado fica `parcial`. Falhas classificadas: `autenticacao` (login recusado, sessão expirada), `indisponibilidade` (rede, página de erro do navegador, HTTP 5xx), `navegacao`, `interface_alterada` (tabela ou coluna obrigatória ausente, HTTP 404, listando as colunas encontradas), `tempo_esgotado`, `configuracao`, `inesperado`. Falhas transitórias são repetidas (`retries`). Registro no JSON, no log e em captura de tela opcional |

As colunas são localizadas **pelo texto do cabeçalho** (em português e inglês, ignorando acentos), não pela
posição, então reordenar colunas na interface não quebra a coleta. Se faltar uma coluna obrigatória, é erro
(`interface_alterada`); se faltar uma das demais colunas da especificação, é aviso e o campo fica `null`.

Os endereços das páginas e os rótulos de colunas padrão estão em
[src/jervis/collectors/sophos.py](../src/jervis/collectors/sophos.py) e **precisam ser validados no tenant
real**. Ajuste sem alterar o código:

```yaml
platforms:
  sophos:
    params:
      retries: 1
      timeout: 45
      dispositivos:
        pages: {computador: /manage/endpoint/computers-list, servidor: /manage/server/servers-list}
        columns: {status_agente: ["Integridade", "Health"]}   # "#3" = 3ª coluna, para colunas sem título
      alertas:
        pages: {alerta: /manage/overview/alerts, incidente: /manage/threat-analysis-center/threat-cases}
        table: {next_page: "button[aria-label='Próxima página']", max_pages: 50}
```

Datas exibidas na tela (português, inglês, relativas como "há 2 horas") também são gravadas padronizadas em
campos `*_iso` (ex.: `ultima_comunicacao_iso`, `data_hora_iso`); o texto original é sempre mantido.

## Acronis Cyber Protect Cloud

Mesmo mecanismo da Sophos (navegação, colunas por cabeçalho, tratamento de falhas), com dois conjuntos:

| Feature | Implementação |
|---|---|
| 3.1 Navegação | Páginas de dispositivos e de atividades do console. Rotas de SPA (`/ui/#/...`) são recarregadas a cada troca, para não ler a tabela da página anterior |
| 3.2 Dispositivos protegidos | `nome`, `status_protecao`, `plano_protecao`, `ultimo_backup`, `proximo_backup` (+ `tipo`, `agente`) |
| 3.3 Tarefas de backup | `nome_tarefa`, `dispositivo`, `ultima_execucao`, `status_backup`, `duracao`, `tamanho`, `mensagem_erro`, além de `ultima_execucao_iso`, `duracao_segundos` e `tamanho_bytes` |
| 3.4 Falhas de backup | Cada registro recebe `situacao_backup` e `motivo` (ex.: `"Backup com falha (status: Falhou). Erro: Acesso negado ao volume C:"`). O resumo em `summary.destaques` aparece no terminal |

Situações possíveis: `falha`, `incompleto` (cancelado, interrompido, parcial),
`sem_protecao`, `nunca_executado`, `desatualizado` (último backup mais antigo que `max_age_hours`,
padrão 26h), `com_avisos`, `em_execucao`, `desconhecido` (status não reconhecido: vale conferir) e `ok`.
O status é interpretado em português e inglês ("Succeeded with warnings" → `com_avisos`,
"Concluído sem erros" → `ok`).

```
acronis: coletando ...
  [OK] dispositivos: 6 | tarefas: 12
  destaque: dispositivos: 1 desatualizado, 1 falha, 1 sem_protecao, 1 nunca_executado, 1 com_avisos
  destaque: tarefas: 1 desatualizado, 1 falha, 1 com_avisos, 1 incompleto, 1 em_execucao
```

O código de saída reflete a **coleta** (0 = coletou tudo), não a saúde dos backups: os problemas encontrados
são dados, registrados em `summary` e em cada registro.

## Zabbix

| Feature | Implementação |
|---|---|
| 4.1 Navegação | Monitoramento → Hosts, Inventário → Hosts, Monitoramento → Problemas e Relatórios → Disponibilidade, por caminhos relativos à URL do Zabbix (funciona em subdiretório, ex.: `/zabbix/`). O login cai no painel (dashboard). Paginação por links que recarregam a página |
| 4.2 Hosts | `nome`, `ip` (+ `porta`, `interface`), `grupo`, `status_monitoramento` (+ `monitorado`), `disponibilidade` (`disponivel`/`indisponivel`/`parcial`/`desconhecido`, lida pela **cor** das etiquetas ZBX/SNMP/IPMI/JMX), `ultima_atualizacao`. A tela de hosts não mostra grupos: eles são cruzados a partir do Inventário |
| 4.3 Problemas | `descricao`, `severidade` (escala do Zabbix: desastre, alta, media, atencao, informacao, nao_classificada; pelo texto ou pela cor da célula), `host`, `data_hora` (+ `_iso`; o Zabbix mostra só a hora para eventos de hoje), `duracao` (+ `duracao_segundos`, entendendo `1M 10d` como meses), `status` (+ `situacao`: ativo/resolvido). Origens: ativos e histórico das últimas 24h |
| 4.4 Indicadores | Relatório de disponibilidade (7 dias): `host`, `indicador`, `ok_pct`, `problema_pct` (números) e `abaixo_da_meta` (meta `min_availability`, padrão 99%). O resumo traz os piores indicadores |

Destaques no terminal: hosts indisponíveis, parciais ou não monitorados; problemas ativos por severidade (o
mesmo problema nas duas origens conta uma vez); indicadores abaixo da meta.

Limitações conhecidas:
- **Grupo** vem do Inventário, que só lista hosts com inventário habilitado; os demais ficam com `grupo: null`.
- **Última atualização** não aparece nas telas de hosts. O conjunto `itens` (Dados recentes, desativado por
  padrão) a preenche com a verificação mais recente de cada host, mas pode ser pesado e é limitado pelo
  "Limite de resultados de busca" do Zabbix (1000 por padrão).
- As listas respeitam as "Linhas por página" do perfil do usuário de coleta; aumentá-las reduz o número de páginas.

## Padronização e consolidação

Ao fim de cada `jervis collect`, os resultados das três plataformas são unificados em
`output/<data-hora>/consolidado.json` e `consolidado.csv` (separado por `;`, abre direto no Excel):

```
Consolidado: 100 registro(s) | crítico: 4 | indisponível: 11 | falha de coleta: 1 | atenção: 10 | normal: 74
```

**Modelo padrão (5.1)** — cada registro tem: `plataforma`, `categoria`, `recurso`, `status` (como exibido na
plataforma), `severidade` (escala comum: critica, alta, media, baixa, informativa), `classificacao`, `prioridade`,
`data_coleta`, `data_evento`, `mensagem`, `observacoes`, além de `ambiente`, `origem`, `id` e `detalhes` (o registro
original, para rastreabilidade). Categorias: `endpoint` e `alerta_seguranca` (Sophos), `protecao_backup` e
`tarefa_backup` (Acronis), `host`, `problema_monitoramento` e `disponibilidade` (Zabbix) e `coleta` (falhas da coleta).

**Limpeza e validação (5.2)** — espaços extras e marcadores de vazio (`—`, `N/A`, `-`) viram vazio; registros
sem campo obrigatório são descartados e listados em `validacao.descartados`; alertas e problemas sem recurso são
atribuídos à própria plataforma; duplicidades são removidas, mantendo o registro mais urgente; datas não
reconhecidas, datas no futuro, severidades fora da escala e percentuais inválidos ficam anotados em `observacoes`.

**Classificação (5.3)** — prioridade 1 para `critico` e `indisponivel`, 2 para `falha_coleta`, 3 para `atencao`,
4 para `normal`. Regras principais:

| Origem | crítico | indisponível | atenção |
|---|---|---|---|
| Sophos endpoint | proteção desligada/comprometida, saúde ruim | agente inativo ou sem comunicação há mais de `stale_device_days` (7) | proteção desatualizada, avisos |
| Sophos alerta (aberto) | severidade crítica/alta | — | média/baixa ou sem severidade |
| Acronis | falha, sem proteção, nunca executado | — | incompleto, desatualizado, com avisos |
| Zabbix host | — | indisponível | parcial, não monitorado |
| Zabbix problema (ativo) | desastre/alta | — | média/atenção ou sem severidade |
| Zabbix disponibilidade | abaixo de `critical_availability_pct` (95%) | — | abaixo da meta (`min_availability`) |
| Falha da coleta | — | — | avisos (erros = `falha_coleta`) |

Alertas e problemas resolvidos são `normal`.

**Consolidação (5.4)** — `consolidado.json` traz `fontes` (situação da coleta de cada plataforma), `resumo`
(totais por classificação, plataforma e categoria), `validacao` e `registros` ordenados por prioridade. Uma plataforma
que não pôde ser coletada aparece como `falha_coleta`, em vez de simplesmente sumir do relatório. `jervis
consolidate` refaz a consolidação a partir dos arquivos salvos (útil após ajustar limites), sem coletar de novo.

## Relatórios

Ao fim de cada `jervis collect` (e com `jervis report`), são gerados em `output/<data-hora>/`:

| Arquivo | Conteúdo |
|---|---|
| `relatorio.html` | Relatório completo em um único arquivo (abre offline em qualquer navegador), com filtros por classificação e busca |
| `relatorio.pdf` | Versão para impressão/envio (A4 paisagem); nas seções por plataforma lista só o que não está normal |
| `relatorio.xlsx` | Abas Resumo, Consolidado, uma por plataforma e Qualidade dos dados; cores por classificação, filtros e datas reais |
| `consolidado.csv`, `relatorio_<plataforma>.csv` | Todos os registros e um arquivo por plataforma (`;`, UTF-8 com BOM para o Excel) |

Estrutura do relatório:
- **Resumo executivo (6.3)**: total de dispositivos (sem contar duas vezes o mesmo nome em plataformas diferentes),
  total de alertas e quantos estão ativos, problemas críticos, backups com falha, hosts indisponíveis e plataformas
  sem resposta. Quando a plataforma de origem não respondeu, o indicador mostra **"—" / "sem dados"**, nunca um zero
  enganoso.
- **Visão consolidada (6.1)**: distribuição por classificação (geral e por plataforma), situação da coleta de cada
  plataforma, totais por categoria e a lista de **prioridades** (tudo o que não está normal, do mais urgente ao menos).
- **Detalhado por plataforma (6.2)**: uma seção por plataforma (Sophos, Acronis, Zabbix e instâncias extras), com os
  registros agrupados por categoria.
- **Identificação visual (6.5)**: cada classificação tem cor, ícone e rótulo (crítico ✖ vermelho, indisponível ⊖ roxo,
  falha de coleta ? cinza, atenção ⚠ âmbar, normal ✔ verde), também no PDF e no Excel. A cor nunca é o único sinal.

O PDF é impresso pelo mesmo navegador usado na coleta (`settings.browser`/`driver_path`); se ele não estiver
disponível, os demais formatos são gerados normalmente e o erro do PDF é informado. Formatos e título:
`settings.report_formats` e `settings.report_title`.
