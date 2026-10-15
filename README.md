# Jervis3000

Ferramenta que coleta dados de segurança, backup e monitoramento dos clientes e gera os
relatórios mensais. A coleta é feita pelas APIs do **Acronis Cyber Protect Cloud** (contas BR e US), do
**Sophos Central** e do **Zabbix**. Todo mês, o Jervis gera sozinho os relatórios de todos os clientes. A equipe
revisa e aprova pelo navegador ou pelo terminal, e depois envia ao cliente.

```
cadastro de clientes ─► coleta por API ─► consolidação e ─► relatórios por ─► revisão ─► envio ao
(MySQL, vínculos com    (Acronis, Sophos,  classificação     cliente (PDF,      (web ou    cliente
 cada plataforma)        Zabbix)           (crítico, atenção) executivo, resumo) terminal) (pela equipe)
```

## O que o Jervis entrega

Cada relatório de cliente fica em `output\clientes\<cliente>\<data-hora>\`:

| Arquivo | Para quem |
|---|---|
| `relatorio_executivo.pdf` | Cliente (diretoria): visão curta, indicadores e recomendações |
| `relatorio_mensal.pdf` (também `.html`) | Cliente: relatório detalhado do mês |
| `relatorio_mensal.xlsx` e `.csv` | Equipe: os registros do mês, para filtrar |
| `resumo.md` | Equipe: texto de apoio para o e-mail ou a reunião com o cliente |

O **fechamento mensal** roda no primeiro dia útil do mês, às 09:00, pelo Agendador do Windows. Ele gera os
relatórios do mês anterior de todos os clientes ativos e deixa cada um pendente de revisão. Também avisa a equipe
no Teams, listando quais clientes saíram completos, com limitações ou com falha.

## Início rápido

Pré-requisitos: Windows, Python 3.12, Docker Desktop e Microsoft Edge (que imprime os PDFs).

```powershell
py -3.12 -m pip install --user uv                     # gerenciador de dependências (uma vez)
py -3.12 -m uv sync                                     # cria o .venv com as versões travadas do uv.lock
.venv\Scripts\python -m jervis init                    # cria config\platforms.yaml
```

**1. Banco de dados (MySQL no Docker):** o passo a passo das senhas está em
[Instalação](docs/instalacao.md#banco-de-dados-e-fila-mysql-e-rabbitmq).

```powershell
docker compose up -d
.venv\Scripts\python -m jervis db set-credentials --username jervis
.venv\Scripts\python -m jervis db generate-key         # guarde uma cópia segura desta chave
.venv\Scripts\python -m jervis db status
```

**2. Plataformas e credenciais de API.** As credenciais ficam no cofre do Windows e são pedidas de forma oculta.

```powershell
.venv\Scripts\python -m jervis services add sophos --url https://api.central.sophos.com --class sophos
.venv\Scripts\python -m jervis services set-api-credentials sophos
.venv\Scripts\python -m jervis services test-api sophos
```

Faça o mesmo para `acronis`, `acronis-us` e `zabbix`
([acesso por API](docs/configuracao.md#acesso-por-api)).

**3. Clientes:** importa os clientes de cada plataforma e vincula ao cadastro.

```powershell
.venv\Scripts\python -m jervis services clients acronis --import
.venv\Scripts\python -m jervis customers duplicates    # revisa cadastros duplicados e de teste
.venv\Scripts\python -m jervis customers list
```

**4. Relatório de um cliente:**

```powershell
.venv\Scripts\python -m jervis customers report "MERCOS" --month 2026-09
```

**5. Fechamento automático** (seção `schedules` em [Configuração](docs/configuracao.md#agendamentos-schedules)):

```powershell
.venv\Scripts\python -m jervis schedule install
.venv\Scripts\python -m jervis schedule list
```

**6. Interface web da equipe:** veja abaixo e o [passo a passo](docs/interface-web.md).

Com o `.venv` ativado, `jervis ...` equivale a `.venv\Scripts\python -m jervis ...`.

## Rotina mensal

1. **Primeiro dia útil, 09:00:** o Jervis gera os relatórios do mês anterior e avisa no canal do Teams. Se o PC
   estiver desligado nesse horário, o fechamento roda quando ele for ligado. Cada mês é fechado uma vez só.
2. **Revisão:** cada relatório é aberto, aprovado ou rejeitado com motivo, pela interface web ou com
   `jervis reviews`. Fica registrado quem aprovou e quando.
3. **Correções:** se um relatório foi rejeitado ou um cliente falhou, gere de novo com
   `jervis customers report "<cliente>" --month AAAA-MM` ou, na interface, com **Gerar de novo** (admin). O novo
   relatório entra como pendente.
4. **Envio:** depois da aprovação, a equipe envia os dois PDFs ao cliente. O Jervis não envia nada sozinho.

Para fechar um mês manualmente (o mesmo que o agendamento faz): `jervis month-close --month AAAA-MM`.

## Interface web

Um site interno (`https://<máquina>:8443`) para a revisão:

- **O que faz:** lista os relatórios por mês e por situação, mostra o detalhe por plataforma e abre os PDFs no
  navegador. Também aprova (um ou vários de uma vez) e rejeita com motivo.
- **Contas próprias do Jervis:** o admin cria o login de cada colega na página **Usuários**, e o Jervis gera uma
  senha temporária. No primeiro acesso, a pessoa cria a senha dela e configura o app autenticador no celular.
- **Perfis:**
  - `leitura`: vê os relatórios;
  - `revisor`: também aprova e rejeita;
  - `admin`: também gera de novo, desfaz revisões e administra as contas.
- **Proteções:** só aceita a rede interna ou a VPN, sempre por HTTPS. Bloqueia a conta após tentativas erradas e
  registra cada ação na trilha de auditoria.

```powershell
jervis web users add voce@contego.com.br --name "Seu Nome" --role admin   # primeira conta (mostra a senha temporária)
jervis web check                                                          # o que falta
jervis web serve                                                          # deixa a janela aberta
```

O firewall, o certificado nos computadores da equipe e a resolução de problemas estão em
[docs/interface-web.md](docs/interface-web.md).

## Comandos

### Relatórios, fechamento e revisão

| Comando | Para quê |
|---|---|
| `jervis customers report <cliente> [--month AAAA-MM \| --days N]` | Coleta por API e gera o relatório mensal, o executivo e o `resumo.md` de um cliente (padrão: o mês atual até hoje). Opções: `--formats`, `--notes`, `--open` e `--ia` (texto do executivo redigido pelo Claude) |
| `jervis customers report --all [--month AAAA-MM]` | O mesmo, para todos os clientes ativos vinculados, um após o outro |
| `jervis month-close [--month AAAA-MM] [--no-notify]` | Fechamento mensal: relatórios de todos os clientes (padrão: o mês anterior), pendentes de revisão, e aviso à equipe |
| `jervis reviews list [--status todos\|pendente\|aprovado\|rejeitado\|falha] [--month AAAA-MM]` | Relatórios gerados e a situação da revisão (padrão: pendentes) |
| `jervis reviews open <cliente\|#id>` | Abre o relatório executivo para revisar |
| `jervis reviews approve <cliente\|#id> [--note "..."]` | Aprova o relatório e mostra os arquivos para enviar |
| `jervis reviews reject <cliente\|#id> --reason "..."` | Rejeita o relatório, com o motivo |

### Interface web

| Comando | Para quê |
|---|---|
| `jervis web serve [--host] [--port]` | Sobe a interface (HTTPS). `Ctrl+C` para |
| `jervis web check` | Confere endereço, certificado, chave do app autenticador e contas |
| `jervis web cert [--name <nome ou IP>] [--force]` | Certificado HTTPS desta máquina, emitido pela autoridade interna do Jervis |
| `jervis web users list` | Contas e situação (ativa, senha temporária, bloqueada, suspensa) |
| `jervis web users add <e-mail> --name "Nome" --role leitura\|revisor\|admin` | Cria uma conta e mostra a senha temporária |
| `jervis web users reset-password <e-mail>` | Nova senha temporária (também desbloqueia a conta) |
| `jervis web users reset-mfa <e-mail>` | Apaga o app autenticador (a pessoa configura de novo) |
| `jervis web users role <e-mail> <perfil>` / `disable` / `enable` | Muda o perfil, suspende ou reativa |

### Clientes

| Comando | Para quê |
|---|---|
| `jervis customers list` / `show <cliente>` | Clientes, serviços vinculados e situação (ativo/inativo) |
| `jervis customers add <nome>` / `update` / `remove` | Cadastro manual |
| `jervis customers link <cliente> <serviço> [--external-name <nome ou id>]` | Vincula a um serviço. Use `--external-name` quando o nome na plataforma for outro, como o id do tenant no Sophos |
| `jervis customers unlink <cliente> <serviço>` | Desfaz o vínculo |
| `jervis customers duplicates` | Sugere cadastros duplicados e de teste (POC, trial), sem alterar nada |
| `jervis customers merge <origem> <destino>` | Junta dois cadastros do mesmo cliente: vínculos e histórico vão para o destino |
| `jervis customers deactivate <cliente> --reason "..."` / `activate` | Inativo fica fora do fechamento mensal e do `--all` |

### Plataformas (serviços) e acesso por API

| Comando | Para quê |
|---|---|
| `jervis services add / list / update / remove` | Plataformas no banco: `acronis`, `acronis-us`, `sophos`, `zabbix` |
| `jervis services set-api-credentials <serviço>` | Credenciais de API no cofre. Acronis e Sophos: client id e secret; Zabbix: token |
| `jervis services test-api <serviço>` | Testa o acesso (só leitura) e lista os clientes encontrados |
| `jervis services clients <serviço> [--import]` | Clientes da plataforma comparados com o cadastro; `--import` cadastra e vincula os que faltam |

### Agendamento, notificações e IA

| Comando | Para quê |
|---|---|
| `jervis schedule list / install / uninstall / run <nome> / serve` | Agendamentos no Agendador de Tarefas do Windows (`serve`: agendador interno em primeiro plano) |
| `jervis notify set-webhook / set-smtp-password / test` | Aviso à equipe pelo Teams (Workflows) e/ou por e-mail |
| `jervis ia set-key / delete-key` | Chave da API do Claude, opcional, para o texto do relatório executivo |

### Banco, operação e auditoria

| Comando | Para quê |
|---|---|
| `jervis db init / status / set-credentials / generate-key` | MySQL: tabelas, credenciais e chave de criptografia |
| `jervis status [--json]` | Saúde da ferramenta: OK, atenção ou crítico (código de saída 0/2/3) |
| `jervis audit [--verify] [--event <evento>]` | Trilha de auditoria: quem gerou, aprovou, entrou na interface ou alterou a configuração |
| `jervis config show` | Configuração efetiva (base + ambiente) |

### Coleta pelo navegador (modo anterior)

O modo original do Jervis, com Selenium e login nas telas das plataformas, continua disponível. Ele serve para o
relatório geral (não por cliente) e para plataformas sem API.

| Comando | Para quê |
|---|---|
| `jervis platforms ...` / `credentials ...` / `login` | Cadastro das plataformas, credenciais de tela e teste de login |
| `jervis check [plataformas]` | Verifica login, páginas e colunas, sem coletar |
| `jervis collect [plataformas] [--retry N]` / `retry` | Coleta e reprocessamento |
| `jervis runs` / `runs show` / `runs prune` | Histórico das execuções e retenção |
| `jervis report` / `consolidate` | Refaz os relatórios ou o consolidado de uma execução |
| `jervis driver status / update [--auto]` | Driver do Edge compatível com a versão instalada |

Opções globais: `--env <ambiente>` (ou `JERVIS_ENV`), `-c <arquivo>` e `-v`.

## Documentação

| Documento | Conteúdo |
|---|---|
| [Instalação](docs/instalacao.md) | Pré-requisitos, ambiente Python, Docker (MySQL e RabbitMQ), driver do navegador, atualização |
| [Configuração](docs/configuracao.md) | Arquivo de configuração, banco, acesso por API, limpeza do cadastro, relatórios por cliente, ambientes, agendamentos, notificações |
| [Execução e operação](docs/execucao.md) | Fechamento mensal e revisão, agendamento, monitoramento da ferramenta, auditoria, coleta pelo navegador |
| [Interface web](docs/interface-web.md) | Contas e perfis, primeiro acesso, firewall, certificado na equipe, problemas comuns |
| [Plataformas e dados coletados](docs/plataformas.md) | O que é coletado de cada plataforma, regras de classificação, relatórios |
| [Solução de problemas](docs/solucao-de-problemas.md) | O que fazer para cada tipo de falha |
| [Estrutura do projeto](docs/estrutura.md) | Arquitetura, módulos, formatos de dados, testes |
| [Inclusão de novas plataformas](docs/novas-plataformas.md) | Passo a passo com exemplo e checklist |
| [Rastreabilidade dos requisitos](docs/requisitos.md) | Onde cada requisito está implementado |

## Segurança

- **Segredos fora dos arquivos:** credenciais de API, senhas do banco, URL do webhook e chave da IA ficam no
  cofre do Windows, separadas por ambiente, ou em variáveis de ambiente. Nunca ficam no código, no arquivo de
  configuração ou no git.
- **Segredos nunca exibidos:** são pedidos de forma oculta no terminal e mascarados em logs, relatórios e
  auditoria.
- **Banco:** as chaves MFA (das plataformas e do app autenticador da interface) ficam criptografadas, com a chave
  gerada por `jervis db generate-key`. As datas ficam em UTC.
- **Interface web:**
  - rede interna e VPN apenas, HTTPS com TLS 1.2 ou mais novo;
  - senhas só como hash (scrypt), app autenticador e bloqueio por tentativas;
  - sessão que cai ao trocar a senha ou suspender a conta;
  - proteção contra requisições forjadas e política de conteúdo restrita.
- **Certificado:** as chaves do certificado HTTPS (`config/web/`) ficam só nesta máquina e fora do git.
- **Auditoria:** a trilha é encadeada por hash (`jervis audit --verify`) e registra quem fez cada ação, inclusive
  na interface web, com o IP.
- **Relatórios:** o conteúdo vindo das plataformas é escapado e limpo de caracteres de controle.

## Testes

```powershell
.venv\Scripts\python -m pytest -q                                  # unitários, integração e navegação (~4 min)
.venv\Scripts\python -m pytest -q --cov=jervis --cov-report=term   # com cobertura
.venv\Scripts\python -m pyflakes src tests                         # verificação estática
```

Detalhes em [Estrutura do projeto](docs/estrutura.md#testes).
