# Rastreabilidade dos requisitos

Onde cada feature do backlog está implementada e como verificá-la.

| Épico / Feature | Implementação | Como verificar |
|---|---|---|
| **1. Acesso seguro às plataformas** | | |
| 1.1 Configuração das plataformas | `config.py`; `jervis platforms list/add/set-url/set/enable/disable/remove` | `jervis platforms list --check` |
| 1.2 Gerenciamento seguro de credenciais | `credentials.py` (cofre do sistema/variáveis), `security.py` (redação) | `jervis credentials set`; `tests/test_credentials.py`, `test_security.py` |
| 1.3 Autenticação automatizada | `auth/authenticator.py`, `auth/mfa.py`, `auth/profiles.py` | `jervis login --headed`; `tests/test_auth_browser.py` |
| **2. Coleta da Sophos** | `collectors/sophos.py` | `tests/test_sophos_*.py` |
| 2.1 Navegação | `collectors/base.py` (páginas, sessão), `collectors/table.py` (paginação) | `jervis check sophos` |
| 2.2 Dispositivos e agentes | conjunto `dispositivos` | [plataformas.md](plataformas.md#sophos-central) |
| 2.3 Alertas e incidentes | conjunto `alertas` | idem |
| 2.4 Tratamento de falhas na coleta | `errors.IssueCategory`, isolamento por página, tentativas | `tests/test_sophos_browser.py` |
| **3. Coleta da Acronis** | `collectors/acronis.py` | `tests/test_acronis_*.py` |
| 3.1 – 3.3 Navegação, dispositivos, tarefas de backup | conjuntos `dispositivos`, `tarefas`; rotas de SPA | `jervis check acronis` |
| 3.4 Falhas de backup | `situacao_backup`/`motivo`, `max_age_hours` | `tests/test_acronis_unit.py` |
| **4. Coleta do Zabbix** | `collectors/zabbix.py` | `tests/test_zabbix_*.py` |
| 4.1 – 4.4 Navegação, hosts, problemas, disponibilidade | conjuntos `hosts`, `inventario`, `problemas`, `disponibilidade`, `itens` | `jervis check zabbix` |
| **5. Padronização e consolidação** | `consolidation/` | `tests/test_consolidation.py` |
| 5.1 Modelo padrão | `consolidation/model.py` (`StandardRecord`) | `consolidado.json` |
| 5.2 Limpeza e validação | `consolidation/cleaning.py` | seção "Qualidade dos dados" do relatório |
| 5.3 Classificação | `consolidation/rules.py` | [plataformas.md](plataformas.md#padronização-e-consolidação) |
| 5.4 Consolidação | `consolidation/consolidate.py` | `jervis consolidate` |
| **6. Relatórios** | `reports/` | `tests/test_reports.py` |
| 6.1 – 6.3 Consolidado, por plataforma, resumo executivo | `reports/data.py`, `reports/slides.py`, `templates/slides.html.j2` | `jervis report --open` |
| 6.4 Excel, CSV, PDF, HTML | `reports/excel.py`, `pdf.py`, `html.py`, CSV | `output/<execução>/relatorio.*` |
| 6.5 Identificação visual | cores + ícones + rótulos por classificação | relatório HTML/PDF/Excel |
| **7. Agendamento e execução** | `runner.py`, `scheduling.py` | `tests/test_runner.py`, `test_scheduling.py` |
| 7.1 Execução manual | `jervis collect` | — |
| 7.2 Agendamento automático | `schedules`, `jervis schedule install/serve` | `jervis schedule list` |
| 7.3 Acompanhamento | progresso, `execucao.json/.log`, `jervis runs` | `jervis runs show` |
| 7.4 Reprocessamento | `jervis retry`, `retries` automáticos | — |
| **8. Logs, auditoria e erros** | | `tests/test_audit_errors.py` |
| 8.1 Logs | `logging_setup.py` (id da execução em cada linha) | `logs/jervis.log` |
| 8.2 Tratamento de erros | categorias de falha, dados incompletos, falha de relatório, erro inesperado | [solução de problemas](solucao-de-problemas.md) |
| 8.3 Histórico | `output/historico.jsonl`, retenção | `jervis runs`, `jervis runs prune` |
| 8.4 Auditoria | `audit.py` (encadeada por hash) | `jervis audit --verify` |
| **9. Qualidade, segurança e manutenção** | | |
| 9.1 Testes automatizados | `tests/` (unitários e integração, ~90% de cobertura) | `pytest --cov=jervis` |
| 9.2 Testes de navegação | testes `browser` com páginas falsas; `jervis check` contra as plataformas reais | `pytest -m browser`; `jervis check` |
| 9.3 Configuração por ambiente | `--env`/`JERVIS_ENV`, `platforms.<env>.yaml`, cofre/pastas/tarefas separados | `jervis --env hml config show`; `tests/test_environments.py` |
| 9.4 Documentação | `README.md`, `docs/` | — |
| 9.5 Monitoramento da ferramenta | códigos de saída 0/2/3, `jervis status`, `status.json`, notificações | `tests/test_health_notify.py` |
