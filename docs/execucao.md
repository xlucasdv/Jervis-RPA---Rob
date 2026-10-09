# Execução e operação

Todos os comandos: `.venv\Scripts\python -m jervis <comando>` (abreviado aqui como `jervis <comando>`).
Opções globais: `-c <arquivo>` (configuração), `--env <ambiente>`, `-v` (logs detalhados no terminal).
Ajuda de qualquer comando: `jervis <comando> --help`.

## Rotina do operador

```powershell
jervis status                # a ferramenta está saudável? (OK / ATENÇÃO / CRÍTICO)
jervis collect               # coleta todas as plataformas ativas, consolida e gera os relatórios
jervis runs                  # histórico das execuções
jervis report --open         # abre o relatório da última execução
jervis retry                 # repete só o que falhou na última execução
```

## Verificar as plataformas: `jervis check`

Faz login e visita cada página configurada, conferindo tabela e colunas, **sem coletar dados**. Use ao
instalar, ao trocar de ambiente e sempre que uma plataforma for atualizada.

```
zabbix — https://zabbix.empresa.com.br/index.php
  login: OK em 2.1s — https://zabbix.empresa.com.br/zabbix.php?action=dashboard.view
  hosts/monitoramento: OK — 50 linha(s) na 1ª página
  problemas/ativo: AVISO — coluna(s) esperada(s) ausente(s): duracao
  disponibilidade/relatorio_7d: FALHA — coluna(s) obrigatória(s) ausente(s): ok_pct
    colunas na tela em disponibilidade/relatorio_7d: Host, Nome, Incidentes, Normal, Gráfico
  Resultado: FALHA — detalhes em logs\verificacao\zabbix-20261006-101500.json
```

`--headed` mostra o navegador; `--screenshots` salva uma captura de cada página em `logs/verificacao/capturas`.
O JSON traz o mapeamento campo → coluna e um registro de exemplo de cada página.

## Coletar: `jervis collect`

```powershell
jervis collect                         # todas as ativas
jervis collect sophos zabbix           # só estas
jervis collect --headed                # mostra o navegador
jervis collect --retry 1 --retry-delay 5   # repete sozinho o que falhar, 5 minutos depois
```

Cada execução cria `output/<data-hora>/` com:

| Arquivo | Conteúdo |
|---|---|
| `<plataforma>.json` | Dados coletados, falhas e avisos de cada plataforma |
| `consolidado.json`, `consolidado.csv` | Dados das três plataformas no modelo padrão, classificados |
| `relatorio.html`, `.pdf`, `.xlsx`, `relatorio_<plataforma>.csv` | Relatórios ([detalhes](plataformas.md#relatórios)) |
| `execucao.json` | Situação da execução, atualizada durante o andamento |
| `execucao.log` | Progresso com horário, como exibido no terminal |

Relatórios de um cliente coletados por API (`jervis customers report`) ficam em `output/clientes/<cliente>/<data-hora>/`:
Relatório Mensal, Relatório Executivo e `resumo.md` ([detalhes](configuracao.md#relatórios-por-cliente-padrão-de-apresentação)).

Só uma coleta roda por vez: um agendamento que dispare durante uma coleta manual é recusado com aviso.

### Códigos de saída

| Código | `collect`, `retry`, `schedule run` | `status` |
|---|---|---|
| 0 | Sucesso em todas as plataformas | OK |
| 1 | Erro de uso ou de configuração (a coleta não começou) | — |
| 2 | Parcial: alguma plataforma ou página falhou, ou um relatório não foi gerado | Atenção |
| 3 | Falha em todas as plataformas | Crítico |

O Agendador de Tarefas mostra esse código em "Resultado da última execução" (0x0, 0x2, 0x3).

## Reprocessar falhas: `jervis retry`

```powershell
jervis retry                               # última execução
jervis retry output\20261006-070000 --platforms acronis
```

Repete só o necessário e refaz consolidado e relatórios da mesma execução:
- falha de **página** (ex.: interface alterada em `alertas/alerta`) → só aquela página;
- falha de **login, acesso ou sessão** → a plataforma inteira;
- erro de **configuração** (ex.: credencial ausente) → não repete: corrija e rode de novo.

## Relatórios e consolidado

```powershell
jervis report --open                       # gera (de novo) os relatórios da última execução e abre o HTML
jervis report --formats pdf,xlsx output\20261006-070000
jervis consolidate                         # refaz o consolidado (ex.: depois de mudar limites de classificação)
```

## Acompanhamento e histórico

```powershell
jervis runs                    # últimas execuções (inclui em andamento e interrompidas)
jervis runs show               # detalhes da última: plataformas, tentativas, falhas, avisos, relatórios
jervis runs show 20261006-070000
jervis runs prune --days 30    # remove pastas antigas (o histórico é mantido)
```

```
EXECUÇÃO         ORIGEM               USUÁRIO           INÍCIO       DURAÇÃO  STATUS               PLATAFORMAS
20261006-070000  agendamento:diaria   EMPRESA\svc_ti    06/10 07:00  95s      PARCIAL (1 aviso(s)) acronis:FALHA sophos:OK zabbix:OK
```

O log geral (`logs/jervis.log`) traz o identificador da execução em cada linha, o que permite filtrar uma
execução: `Select-String -Path logs\jervis.log -Pattern "20261006-070000"`.

## Agendamento

1. Defina os horários na seção `schedules` ([configuração](configuracao.md#agendamentos-schedules)).
2. Confira e registre:

```powershell
jervis schedule list                 # quando roda, próxima execução, se está registrado no Windows
jervis schedule install --dry-run    # mostra os comandos do Agendador de Tarefas
jervis schedule install              # registra (pasta "Jervis3000" do Agendador de Tarefas)
jervis schedule uninstall            # remove
jervis schedule run diaria           # executa um agendamento agora, exatamente como a tarefa faria
```

- As tarefas rodam com o **seu usuário do Windows**, que tem acesso às credenciais cadastradas, enquanto você
  estiver conectado. Para rodar com a sessão desconectada: Agendador de Tarefas → pasta `Jervis3000` →
  Propriedades da tarefa → "Executar estando o usuário conectado ou não" (o Windows pedirá a senha).
- Execuções agendadas usam o navegador oculto e exigem `mfa: totp` (não há quem digite um código).
- A saída de cada tarefa fica em `logs/agendamento-<nome>.log`.
- Ative `jervis driver update --auto`: o Edge se atualiza sozinho e, sem isso, as coletas agendadas param
  quando a versão principal muda ([instalação](instalacao.md#driver-do-navegador-em-máquinas-corporativas)).
- Sem acesso ao Agendador de Tarefas (ou fora do Windows): `jervis schedule serve` mantém um agendador em
  primeiro plano com as mesmas regras.

## Monitoramento da própria ferramenta

### `jervis status`

```
Saúde da ferramenta: CRÍTICO
  - acronis: 31.5 h sem coleta bem-sucedida (limite: 26 h).
  - Última execução (20261006-070000) parcial: acronis.
Última execução: 20261006-070000 (agendamento:diaria) — PARCIAL
```

| Saúde | Quando |
|---|---|
| OK | Última execução bem-sucedida e todas as plataformas ativas com sucesso dentro do limite |
| Atenção | Última execução parcial, com avisos, relatório incompleto ou execução interrompida |
| Crítico | Última execução falhou, nenhuma execução registrada, ou plataforma ativa há mais de `max_hours_without_success` horas sem sucesso |

O mesmo conteúdo fica em `output/status.json`, atualizado ao fim de cada execução, e sai em JSON com
`jervis status --json`.

### Monitorando pelo Zabbix

O próprio Zabbix pode vigiar a ferramenta lendo o `status.json` com o agente instalado na máquina:

- Item `vfs.file.contents[C:\Jervis3000\output\status.json]` (tipo texto), com pré-processamento JSONPath
  `$.saude`.
- Gatilho: valor diferente de `ok`, com severidade Atenção para `atencao` e Alta para `critico`.
- Item `vfs.file.time[C:\Jervis3000\output\status.json,modify]` + gatilho de "arquivo não atualizado há mais
  de 26 h", para detectar o caso em que as execuções pararam completamente (tarefa desativada, máquina
  desligada).

### Notificações

Com a seção `notifications` configurada, cada execução que termine em uma das situações de `when` envia e-mail
e/ou mensagem de webhook (Teams, Slack ou JSON), com o resumo por plataforma, as falhas e o caminho do
relatório. Uma falha ao notificar não interrompe a execução: fica registrada em `jervis runs show` e na
auditoria. `jervis notify test` envia uma mensagem de teste.

## Auditoria

```powershell
jervis audit                         # últimos eventos
jervis audit --event credencial      # filtra por tipo
jervis audit --verify                # confere se a trilha foi alterada
```

Registra quem (usuário do Windows e máquina), quando e o quê: coletas e reprocessamentos (com plataformas e
conta de serviço usada, mascarada) e ações administrativas (plataformas, credenciais, agendamentos,
notificações, retenção). Cada evento guarda o hash do anterior, então alterar ou apagar uma linha quebra a
cadeia. Para proteção contra exclusão do arquivo inteiro, restrinja a escrita na pasta `logs/` ou envie o
arquivo para um repositório central (SIEM).
