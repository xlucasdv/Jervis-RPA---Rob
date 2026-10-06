# Estrutura do projeto

## Fluxo de uma execução

```
jervis collect / schedule run
        │
        ▼
runner.Runner ──── trava (uma execução por vez), progresso, execucao.json, histórico, auditoria
        │
        ├─ para cada plataforma ──► collection.run_collection
        │                              ├─ session.platform_session ── browser.create_driver + auth.FormLoginAuthenticator
        │                              └─ collectors.<Tipo>Collector.collect
        │                                    └─ por página: navegação ─► table.TableScraper ─► normalização
        │                                                     (falhas viram Issue com IssueCategory)
        │                           ◄── CollectionResult  ─► output/<execução>/<plataforma>.json
        │
        ├─ completude (compara com a última coleta bem-sucedida) e reprocessamento automático
        ├─ consolidation.consolidate ─► consolidado.json / .csv   (modelo padrão + classificação)
        ├─ reports.generate_reports  ─► relatorio.html / .pdf / .xlsx / .csv
        └─ notify.Notifier + health.write_status ─► e-mail/webhook, output/status.json
```

## Módulos

```
src/jervis/
  cli.py              comandos "jervis ..." (argparse); só orquestra, sem regra de negócio
  config.py           arquivo YAML: validação, ambientes (base + platforms.<env>.yaml), gravação
  credentials.py      cofre do sistema (keyring) e variáveis de ambiente; cofre separado por ambiente
  security.py         SecretStr e redação de segredos em logs, JSON, relatórios e auditoria
  logging_setup.py    log geral rotativo, com id da execução em cada linha
  errors.py           exceções e categorias de falha (IssueCategory)
  browser.py          criação do WebDriver (Edge/Chrome/Firefox, driver aprovado)
  session.py          platform_session(): navegador autenticado, fechado ao final
  auth/
    profiles.py       seletores de login padrão por tipo de plataforma (LoginProfile)
    authenticator.py  login adaptativo (1 ou 2 etapas, MFA, sessão reaproveitada, detecção de erro)
    mfa.py            códigos TOTP e digitação manual
  collectors/
    base.py           Collector: conjuntos, navegação, tentativas, falhas, inspeção (jervis check)
    table.py          TableScraper: tabela paginada lida por cabeçalho (sinônimos PT/EN, colspan, cores)
    parsing.py        datas (inclusive relativas), durações, tamanhos e percentuais exibidos nas telas
    models.py         CollectionResult, Issue
    sophos.py | acronis.py | zabbix.py   páginas, colunas, normalização e destaques de cada plataforma
  collection.py       run_collection(), gravação do resultado, etapas com falha e mesclagem de reprocessamento
  consolidation/
    model.py          StandardRecord, classificações, prioridades, categorias
    cleaning.py       limpeza, validação, remoção de duplicidades, consistência
    rules.py          conversão e classificação por (tipo de plataforma, conjunto)
    consolidate.py    consolidado.json/.csv
  reports/
    data.py           indicadores executivos, seções por plataforma, cores e ícones
    html.py + templates/report.html.j2   relatório HTML (também a base do PDF)
    excel.py | pdf.py                    Excel e impressão do HTML em PDF pelo navegador
  runner.py           execução completa: trava, progresso, completude, reprocessamento, histórico, retenção
  scheduling.py       regras de horário, Agendador de Tarefas do Windows, agendador interno
  check.py            verificação de login/páginas/colunas sem coletar (jervis check)
  health.py           saúde da ferramenta (jervis status, status.json)
  notify.py           e-mail e webhook
  audit.py            trilha de auditoria encadeada por hash
  diagnostics.py | fileutil.py          capturas de tela de falhas; gravação atômica de arquivos
tests/
  fixtures/site/      páginas falsas: login (Zabbix-like e duas etapas), Sophos, Acronis (SPA) e Zabbix
  test_*.py           testes unitários, de integração e de navegação (marcados "browser")
config/               platforms.yaml (local, fora do controle de versão) e platforms.<env>.yaml
docs/                 esta documentação
```

## Princípios

- **Segredos fora do código e do arquivo de configuração.** Toda saída passa pela redação de segredos.
- **Falhas isoladas.** Uma página ou plataforma com problema não impede as demais; tudo vira `Issue`
  classificado e o resultado fica `parcial`, nunca some.
- **Telas lidas pelo cabeçalho, não pela posição.** Reordenar colunas na plataforma não quebra a coleta;
  coluna obrigatória ausente vira `interface_alterada` com a lista do que existe na tela.
- **Configuração em vez de código** para o que muda entre ambientes e versões: endereços, rótulos de colunas,
  seletores, limites.
- **Texto original sempre preservado** ao lado dos valores interpretados (`*_iso`, `*_segundos`, `*_bytes`,
  `situacao_*`).
- **Gravação atômica** de resultados e configuração: nada fica pela metade se o processo for interrompido.

## Formato dos dados

- `<plataforma>.json`: `platform`, `kind`, `environment`, `started_at`, `finished_at`, `status`
  (`sucesso`/`parcial`/`falha`), `attempts`, `counts`, `summary` (destaques), `issues` (etapa, categoria,
  mensagem, severidade `erro`/`aviso`, URL, captura) e `datasets` (registros por conjunto).
- `consolidado.json`: `fontes`, `resumo`, `validacao` e `registros` no modelo padrão
  ([detalhes](plataformas.md#padronização-e-consolidação)).
- `execucao.json` / `historico.jsonl`: id, origem, ambiente, usuário, máquina, estado, status, duração,
  plataformas (status, tentativas, contagens, falhas, avisos), relatórios, reprocessamentos.
- `auditoria.jsonl`: `em`, `evento`, `usuario`, `maquina`, `ambiente`, `detalhes`, `hash_anterior`, `hash`.

## Testes

```powershell
.venv\Scripts\python -m pytest -q                                   # tudo (~2 min)
.venv\Scripts\python -m pytest -q -m "not browser"                  # só unitários e integração (segundos)
.venv\Scripts\python -m pytest -q --cov=jervis --cov-report=term    # com cobertura
.venv\Scripts\python -m pyflakes src tests                          # verificação estática
```

- **Unitários e de integração**: configuração, credenciais (cofre em memória: o cofre real nunca é tocado),
  interpretação de valores, regras de classificação, consolidação, relatórios, agendamento (Agendador de
  Tarefas simulado), execução e reprocessamento (coleta simulada), auditoria, saúde, notificações (SMTP e
  webhook simulados), CLI.
- **Navegação** (`-m browser`): Edge oculto contra as páginas falsas de `tests/fixtures/site`, servidas
  localmente. Cobrem login em uma e duas etapas, MFA, senha errada, sessão expirada; tabelas paginadas por
  clique e por recarga, SPA com rotas por fragmento, cabeçalhos mesclados, colunas sem título, cores de
  status, interface alterada, carregamento infinito, falha transitória e plataforma fora do ar.
- Se o Selenium Manager estiver bloqueado, aponte um driver: `$env:JERVIS_TEST_DRIVER_PATH = "C:\...\msedgedriver.exe"`.
  Sem driver, os testes de navegação são pulados (e o resumo do pytest mostra quantos).
- As páginas falsas validam a **lógica**; os **seletores reais** de cada plataforma se validam com
  `jervis check` contra o ambiente de cada cliente.
