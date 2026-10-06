# Configuração

Toda a configuração não sensível fica em `config/platforms.yaml` (criado por `jervis init` a partir de um
modelo comentado). Credenciais e segredos **nunca** ficam nesse arquivo: a ferramenta recusa chaves como
`password`, `senha`, `token` ou `secret`.

Para ver a configuração efetiva (já combinada com o arquivo do ambiente, se houver): `jervis config show`.

## Estrutura do arquivo

```yaml
settings: {...}        # parâmetros gerais
platforms: {...}       # uma entrada por plataforma consultada
schedules: {...}       # agendamentos (opcional)
notifications: {...}   # avisos por e-mail/webhook (opcional)
```

## `settings`

| Chave | Padrão | Para que serve |
|---|---|---|
| `browser` | `edge` | `edge`, `chrome` ou `firefox` |
| `driver_path` | vazio | Driver aprovado, quando o download automático é bloqueado ([instalação](instalacao.md)) |
| `headless` | `true` | `false` mostra o navegador (útil para investigar). Agendamentos sempre usam `true` |
| `page_load_timeout` | `60` | Segundos para uma página carregar |
| `login_timeout` | `30` | Segundos aguardando cada etapa do login |
| `collect_timeout` | `30` | Segundos aguardando cada tabela da coleta |
| `log_file` | `logs/jervis.log` | Log geral (rotativo, 5 × 5 MB) |
| `output_dir` | `output` | Resultados, relatórios e histórico |
| `screenshot_on_failure` | `false` | Salva a tela no momento de uma falha (diagnóstico) |
| `screenshot_dir` | `logs/screenshots` | Onde salvar essas capturas |
| `stale_device_days` | `7` | Endpoint Sophos sem comunicação há mais dias = indisponível |
| `critical_availability_pct` | `95.0` | Indicador Zabbix abaixo deste % = crítico |
| `report_formats` | `[html, xlsx, csv, pdf]` | Relatórios gerados ao fim de cada coleta |
| `report_title` | `Relatório geral de TI` | Título dos relatórios |
| `audit_file` | `logs/auditoria.jsonl` | Trilha de auditoria |
| `retention_days` | `90` | Pastas de execução mais antigas são removidas (0 = nunca) |
| `incomplete_drop_pct` | `50` | Queda de registros, frente à última coleta, que gera aviso de dados incompletos |
| `max_hours_without_success` | `26` | `jervis status` fica crítico se uma plataforma ativa passar disso sem sucesso |

## `platforms`

```yaml
platforms:
  zabbix:
    kind: zabbix               # sophos | acronis | zabbix (padrão: o próprio nome)
    enabled: true              # só plataformas ativas são consultadas
    url: https://zabbix.empresa.com.br/index.php
    environment: producao      # rótulo exibido nos relatórios
    description: Zabbix matriz
    mfa: none                  # none | totp | prompt
    login_timeout: 45          # opcional: sobrescreve settings.login_timeout
    selectors: {...}           # opcional: seletores de login (abaixo)
    params: {...}              # opcional: ajustes da coleta (abaixo)
```

Mais de uma instância do mesmo tipo é permitida (ex.: `zabbix_filial` com `kind: zabbix`). Os comandos
`jervis platforms add | set-url | set | enable | disable | remove` alteram este arquivo (comentários não são
preservados nessas alterações).

### Seletores de login (`selectors`)

Cada campo aceita um seletor CSS ou uma lista (o primeiro elemento visível é usado). Os padrões por tipo estão
em `src/jervis/auth/profiles.py`.

| Campo | Elemento |
|---|---|
| `username`, `password` | Campos de usuário e senha |
| `submit` | Botão de entrar |
| `next` | Botão "Avançar" de logins em duas etapas (usuário → senha) |
| `error` | Mensagem de erro exibida pela plataforma (ex.: senha incorreta) |
| `mfa_input`, `mfa_submit` | Campo e botão do código de verificação |
| `success` | Elemento que só aparece depois do login (ex.: menu lateral) |
| `success_url` | Expressão regular da URL depois do login |

```yaml
    selectors:
      error: [".mensagem-erro", "[role='alert']"]
      success_url: ['^https://[^/]+/ui/']
```

### Ajustes da coleta (`params`)

| Chave | Padrão | Para que serve |
|---|---|---|
| `timeout` | `settings.collect_timeout` | Segundos aguardando cada tabela desta plataforma |
| `retries` | `1` | Novas tentativas por página em falhas transitórias |
| `date_order` | `auto` | Leitura de datas como `06/10/2026`: `auto` (dia/mês, salvo se houver AM/PM), `dmy` ou `mdy` |
| `max_age_hours` | `26` | **Acronis**: backup mais antigo que isso é "desatualizado" |
| `min_availability` | `99.0` | **Zabbix**: meta de disponibilidade dos indicadores |
| `<conjunto>` | — | Endereços, colunas e seletores de tabela de um conjunto de dados |

Conjuntos por tipo: Sophos `dispositivos`, `alertas`; Acronis `dispositivos`, `tarefas`; Zabbix `hosts`,
`inventario`, `problemas`, `disponibilidade`, `itens` (este desativado por padrão). Detalhes do que cada um
coleta: [Plataformas e dados coletados](plataformas.md).

```yaml
    params:
      retries: 2
      dispositivos:
        pages:                                   # origem: caminho (relativo à URL após o login) ou URL completa
          computador: /manage/endpoint/computers-list
          servidor: /manage/server/servers-list
        columns:                                 # campo: rótulos aceitos no cabeçalho da tela
          status_agente: ["Integridade", "Health"]
          severidade: ["#1"]                     # "#1" = 1ª coluna (para colunas sem título)
        table:                                   # seletores CSS da tabela, se o layout fugir do padrão
          next_page: "button[aria-label='Próxima página']"
          max_pages: 50
      alertas:
        pages: {}                                # {} desativa o conjunto
```

As colunas são localizadas pelo **texto do cabeçalho** (português ou inglês, sem diferenciar acentos e
maiúsculas). `jervis check` mostra as colunas que existem na tela para facilitar esses ajustes.

## Credenciais

Guardadas no cofre do sistema operacional (no Windows, o Gerenciador de Credenciais, entrada `jervis3000`):

```powershell
jervis credentials set zabbix --username svc_coleta            # senha pedida de forma oculta, com confirmação
jervis credentials set sophos --username coleta@empresa.com.br --totp
jervis credentials delete zabbix
```

- **TOTP (Sophos):** o "segredo" é a chave em texto (base32) exibida ao configurar o aplicativo autenticador
  do usuário de serviço, normalmente na opção "não consigo ler o QR code".
- **Variáveis de ambiente** têm prioridade sobre o cofre, para servidores e automações:
  `JERVIS_<PLATAFORMA>_USERNAME`, `JERVIS_<PLATAFORMA>_PASSWORD`, `JERVIS_<PLATAFORMA>_TOTP_SECRET`
  (ex.: `JERVIS_ZABBIX_HML_PASSWORD` para a plataforma `zabbix_hml`).
- As credenciais são do **usuário do Windows** que as cadastrou: execute os agendamentos com esse mesmo usuário.
- `jervis platforms list` mostra, para cada plataforma, se há credencial e de onde ela vem.

## Ambientes (desenvolvimento, homologação, produção)

A configuração base (`config/platforms.yaml`) vale para todos os ambientes. Cada ambiente tem um arquivo com
**apenas o que muda**:

```powershell
jervis --env hml init                          # cria config\platforms.hml.yaml (modelo comentado)
jervis --env hml platforms set-url zabbix https://zabbix-hml.empresa.com.br/index.php
jervis --env hml credentials set zabbix --username svc_coleta_hml
jervis --env hml collect
```

```yaml
# config/platforms.hml.yaml
settings:
  headless: false
platforms:
  zabbix:
    url: https://zabbix-hml.empresa.com.br/index.php
    enabled: true
```

O ambiente também pode ser escolhido pela variável `JERVIS_ENV=hml`. Em um ambiente, **ficam separados
automaticamente**:

| O quê | Base | Ambiente `hml` |
|---|---|---|
| Resultados, relatórios, histórico, `status.json` | `output/` | `output/hml/` |
| Log geral, auditoria, capturas | `logs/` | `logs/hml/` |
| Credenciais | cofre `jervis3000` | cofre `jervis3000-hml` |
| Tarefas agendadas | `Jervis3000\` | `Jervis3000\hml\` |

Comandos que alteram a configuração (`platforms set-url`, `enable`...) com `--env` gravam no arquivo do
ambiente só a diferença em relação à base. Regras da combinação: mapeamentos são mesclados; listas e valores
simples são substituídos.

## Agendamentos (`schedules`)

```yaml
schedules:
  diaria:
    frequency: daily               # daily (diaria) | weekly (semanal) | hourly (horas)
    times: ["07:00", "18:00"]      # use aspas: sem elas o YAML pode ler 07:00 como número
  semanal:
    frequency: weekly
    days: [mon, thu]               # mon..sun ou seg, ter, qua, qui, sex, sab, dom
    times: ["08:00"]
  zabbix_4h:
    frequency: hourly
    every_hours: 4                 # 1 a 23
    start: "06:00"                 # 06:00, 10:00, 14:00, 18:00, 22:00, 02:00
    platforms: [zabbix]            # padrão: todas as plataformas ativas
    retries: 1                     # reprocessamentos automáticos (padrão 1)
    retry_delay_minutes: 10
    enabled: true
```

Registro no Windows e operação: [Execução](execucao.md#agendamento).

## Notificações (`notifications`)

```yaml
notifications:
  when: [parcial, falha]           # sucesso | parcial | falha
  email:
    smtp_host: smtp.empresa.com.br
    smtp_port: 587
    starttls: true                 # ou ssl: true (porta 465)
    sender: jervis@empresa.com.br
    recipients: [ti@empresa.com.br, noc@empresa.com.br]
    username: jervis@empresa.com.br  # omita se o relay não exige autenticação
    attach_report: true            # anexa o relatorio.html (até 10 MB)
  webhook: true
  webhook_format: teams            # teams (Workflows/Adaptive Card) | slack | json
```

Os segredos vão para o cofre: `jervis notify set-smtp-password` e `jervis notify set-webhook` (a URL do webhook
contém um token). Teste com `jervis notify test`.
