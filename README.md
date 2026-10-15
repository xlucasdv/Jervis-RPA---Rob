# Jervis3000

Ferramenta em Python + Selenium que acessa, de forma autorizada e automatizada, as plataformas
**Sophos Central**, **Acronis Cyber Protect Cloud** e **Zabbix**, coleta informações de segurança, backup e
monitoramento, padroniza e classifica os dados e gera um relatório geral (HTML, PDF, Excel e CSV), manualmente
ou de forma agendada.

```
login automatizado ─► coleta das 3 plataformas ─► consolidação e classificação ─► relatórios ─► notificação
  (credenciais no       (falhas isoladas por         (crítico, indisponível,       (resumo        (e-mail,
   cofre do sistema)     página, reprocessáveis)      falha de coleta, atenção)     executivo)     Teams)
```

## Início rápido

```powershell
py -3.12 -m pip install --user uv                     # gerenciador de dependências (uma vez)
py -3.12 -m uv sync                                     # cria o .venv com as versões travadas do uv.lock
.venv\Scripts\python -m jervis init                    # cria config\platforms.yaml
.venv\Scripts\python -m jervis platforms set-url zabbix https://zabbix.empresa.com.br/index.php
.venv\Scripts\python -m jervis credentials set zabbix --username svc_coleta
.venv\Scripts\python -m jervis platforms enable zabbix
.venv\Scripts\python -m jervis check zabbix --headed   # valida login, páginas e colunas, sem coletar
.venv\Scripts\python -m jervis collect                 # coleta, consolida e gera os relatórios
.venv\Scripts\python -m jervis report --open
```

Em máquinas com política de controle de aplicativos, rode antes `jervis driver update --auto`, que baixa e
mantém atualizado o driver do Edge ([instalação](docs/instalacao.md#driver-do-navegador-em-máquinas-corporativas)).

## Documentação

| Documento | Conteúdo |
|---|---|
| [Instalação](docs/instalacao.md) | Pré-requisitos, ambiente Python, driver do navegador, primeira configuração, atualização |
| [Configuração](docs/configuracao.md) | Arquivo de configuração, plataformas, seletores, ajustes de coleta, credenciais, **ambientes** (dev/hml/prod), agendamentos, notificações |
| [Execução e operação](docs/execucao.md) | Verificação, coleta, reprocessamento, relatórios, histórico, agendamento, **monitoramento da ferramenta**, auditoria |
| [Plataformas e dados coletados](docs/plataformas.md) | O que é coletado de cada plataforma, modelo padrão, regras de classificação, relatórios |
| [Solução de problemas](docs/solucao-de-problemas.md) | O que fazer para cada tipo de falha (login, interface alterada, tempo esgotado, driver, agendamento...) |
| [Estrutura do projeto](docs/estrutura.md) | Arquitetura, módulos, formatos de dados, testes |
| [Inclusão de novas plataformas](docs/novas-plataformas.md) | Passo a passo com exemplo e checklist |
| [Rastreabilidade dos requisitos](docs/requisitos.md) | Onde cada feature dos 9 épicos está implementada e como verificá-la |

## Comandos

| Comando | Para quê |
|---|---|
| `jervis status` | Saúde da ferramenta: OK / atenção / crítico (código de saída 0/2/3) |
| `jervis check [plataformas]` | Verifica login, páginas e colunas nas plataformas reais, sem coletar |
| `jervis collect [plataformas]` | Coleta, consolida e gera relatórios (`--retry N` para reprocessar sozinho) |
| `jervis retry [execução]` | Reprocessa só as plataformas/páginas que falharam |
| `jervis runs` / `runs show` / `runs prune` | Histórico e detalhes das execuções; retenção |
| `jervis report` / `consolidate` | Refaz relatórios ou consolidado de uma execução |
| `jervis schedule list / install / uninstall / run / serve` | Agendamento (Agendador de Tarefas do Windows ou interno) |
| `jervis platforms ...` / `credentials ...` | Cadastro das plataformas e das credenciais (cofre do sistema) |
| `jervis login [plataformas]` | Testa só o login |
| `jervis driver status / update [--auto]` | Versão do driver do Edge; baixa o compatível (e mantém atualizado) |
| `jervis notify set-smtp-password / set-webhook / test` | Notificações por e-mail e Teams/Slack |
| `jervis audit [--verify]` | Trilha de auditoria (quem coletou e quem alterou a configuração) |
| `jervis config show` | Configuração efetiva (base + ambiente) |
| `jervis customers duplicates / merge / deactivate / activate` | Limpeza do cadastro: sugestões de duplicados e POCs, junção de cadastros, clientes inativos (fora do fechamento) |
| `jervis customers add / list / show / update / remove / link / unlink` | Clientes no banco e os serviços de cada um (com chave MFA criptografada) |
| `jervis month-close [--month AAAA-MM]` | Fechamento mensal: relatórios do mês anterior de todos os clientes, pendentes de revisão, com aviso no Teams (agendável: `task: relatorios_clientes`) |
| `jervis reviews list / open / approve / reject` | Revisão dos relatórios por cliente antes do envio (registra quem aprovou e quando) |
| `jervis web serve / check / cert / users` | Interface web da equipe para a revisão, com contas próprias, app autenticador e perfis ([passo a passo](docs/interface-web.md)) |
| `jervis services set-api-credentials / test-api <serviço>` | Credenciais de API no cofre (Acronis, Sophos Central, Zabbix, Desk Manager) e teste de acesso |
| `jervis customers report <cliente> \| --all [--month AAAA-MM] [--ia]` | Coleta por API (Acronis, Sophos Central, Zabbix) e gera o Relatório Mensal, o Relatório Executivo e o `resumo.md` (padrão: mês atual); `--all`: todos os clientes vinculados |
| `jervis services clients <serviço> [--import]` | Clientes que existem no Acronis/Sophos/Zabbix x cadastro; `--import` cadastra e vincula os que faltam |
| `jervis ia set-key / delete-key` | Chave da API do Claude no cofre (texto opcional do relatório executivo) |
| `jervis services add / list / update / remove` | Serviços (plataformas) no banco: url, slug, classe do coletor e configurações |
| `jervis db init / status / set-credentials / generate-key` | Banco MySQL: tabelas, credenciais e chave que criptografa as chaves MFA |

Opções globais: `--env <ambiente>` (ou `JERVIS_ENV`), `-c <arquivo>`, `-v`. Use sempre
`.venv\Scripts\python -m jervis ...`.

## Segurança

- Credenciais e segredos (senhas, TOTP, senha do SMTP, URL do webhook) ficam no cofre do sistema operacional,
  separado por ambiente, ou em variáveis de ambiente, **nunca** no código ou no arquivo de configuração.
- Senhas são mascaradas em logs, resultados, relatórios e auditoria; usuários aparecem parcialmente mascarados.
- Conteúdo lido das plataformas é escapado nos relatórios HTML.
- Trilha de auditoria encadeada por hash (`jervis audit --verify`).

## Testes

```powershell
.venv\Scripts\python -m pytest -q                                  # unitários, integração e navegação (~2 min)
.venv\Scripts\python -m pytest -q --cov=jervis --cov-report=term   # com cobertura
```

Detalhes em [Estrutura do projeto](docs/estrutura.md#testes).
