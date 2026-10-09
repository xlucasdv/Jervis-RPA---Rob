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
| `browser_profile` | vazio | Vazio: janela anônima e limpa a cada execução. Uma pasta (ex.: `perfil_navegador`): janela normal com perfil próprio, que guarda cookies e sessões entre execuções; ver nota abaixo |
| `report_company` | `Contego Security` | Nome exibido na capa e no rodapé dos relatórios |
| `report_logo` | vazio | Caminho do logo (PNG/SVG/JPG) da capa e do rodapé; vazio = ícone + nome |
| `driver_auto_update` | `false` | Edge: confere o driver antes de cada coleta e baixa o da versão do Edge instalado (`jervis driver update --auto`) |
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

### Janela anônima ou normal (`browser_profile`)

- **Vazio (padrão):** cada execução abre uma janela anônima e limpa. Nada fica salvo; todo login é feito do zero
  (inclusive o MFA).
- **Uma pasta** (ex.: `browser_profile: perfil_navegador`): janela normal com um perfil próprio da ferramenta,
  separado do seu Edge pessoal. Cookies e sessões ficam salvos entre execuções: se a sessão ainda for válida, o
  login é reaproveitado, e "Confiar neste navegador" no MFA vale para as próximas execuções.
- **Atenção:** a pasta passa a guardar sessões abertas nas plataformas. Quem tiver acesso a ela, com o seu
  usuário do Windows, pode reaproveitá-las. Ela está no `.gitignore` (`perfil_navegador/`); não a copie nem
  compartilhe. Para "deslogar" tudo, apague a pasta.
- Uma janela por vez usa o perfil: se outra execução estiver com ele aberto, a nova avisa e não inicia.

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

## Banco de dados (`database`)

```yaml
database:
  host: 127.0.0.1
  port: 3306
  name: jervis3000
  connect_timeout: 10      # segundos
```

- Sem a seção `database`, a ferramenta funciona como antes, sem banco.
- Com ela, **ao iniciar qualquer comando** as tabelas que ainda não existem são criadas (`CREATE TABLE IF NOT
  EXISTS`). Banco fora do ar gera só um aviso; os comandos que não usam o banco seguem normalmente.
- Usuário e senha do MySQL ficam no cofre (`jervis db set-credentials`) ou em `JERVIS_DATABASE_USERNAME` /
  `JERVIS_DATABASE_PASSWORD`, nunca no arquivo.

| Tabela | Colunas | Para quê |
|---|---|---|
| `customers` | `id`, `name` (nome do cliente), `desk_manager_id` (único), `created_at`, `updated_at` | Clientes atendidos |
| `service` | `id`, `slug` (único), `url`, `class_identifier`, `settings` (JSON), `mfa_secret_encrypted`, `created_at`, `updated_at` | Plataformas e suas configurações; `class_identifier` aponta o coletor (ex.: `acronis`). A chave MFA é a da **conta de parceiro** |
| `customer_services` | `id`, `customer_id` → customers, `service_id` → service, `external_name`, `mfa_secret_encrypted`, `created_at`, `updated_at` | Serviços de cada cliente; um par cliente+serviço por linha. `external_name` = nome do cliente na plataforma (vazio = `customers.name`) |

- **Conta de parceiro:** cada plataforma usa uma conta da Contego que enxerga todos os clientes. Usuário e senha
  ficam no cofre pelo slug (`jervis services set-credentials acronis`); a chave MFA, em `service`.
- **Chave MFA:** `mfa_secret_encrypted` guarda o segredo TOTP **criptografado** (Fernet). A do vínculo é opcional
  (cliente com conta própria) e, quando existe, tem prioridade sobre a do serviço. A chave de
  criptografia fica no cofre (`jervis db generate-key`) ou em `JERVIS_MFA_ENCRYPTION_KEY`, nunca no banco.
- Apagar um cliente apaga os vínculos dele em `customer_services`; um serviço em uso não pode ser apagado.

### Cadastro pela linha de comando

```powershell
jervis services add acronis --url https://br02-cloud.acronis.com --class acronis --set mfa=totp
jervis services list
jervis services update acronis --set login_timeout=45 --unset mfa
jervis services set-credentials acronis --username parceiro@contego.com.br   # senha pedida oculta
jervis services update acronis --mfa             # chave MFA da conta de parceiro (oculta, criptografada)
jervis customers add "MERCOS" --desk-manager-id 123
jervis customers link "MERCOS" acronis --external-name "MERCOS"   # nome do cliente dentro do Acronis
jervis customers link "MERCOS" acronis --mfa     # só se o cliente tiver conta própria: chave MFA do vínculo
jervis customers link "MERCOS" acronis --clear-mfa
jervis customers list                            # "acronis → MERCOS" = nome na plataforma
jervis customers show 123                        # pelo id, pelo id do Desk Manager ou pelo nome
jervis customers unlink "MERCOS" acronis
jervis customers remove "MERCOS"                 # pede confirmação; leva os vínculos junto
jervis services remove acronis                   # só sem clientes vinculados
```

- `--class`: um tipo de coletor (`acronis`, `sophos`, `zabbix`) ou o caminho de uma classe (`pacote.modulo.Classe`).
- `--set CHAVE=VALOR` aceita números, `true`/`false` e JSON; chaves que parecem credenciais são recusadas.
- A chave MFA nunca é exibida: nem na listagem, nem na auditoria.

## Relatórios por cliente (padrão de apresentação)

```powershell
jervis customers report "MERCOS"                    # mês atual, do dia 1 até agora
jervis customers report "MERCOS" --month 2026-11    # quando novembro chegar (mês futuro é recusado)
jervis customers report "MERCOS" --days 7           # em vez do mês: últimos N dias
jervis customers report "MERCOS" --notes notas.yaml --open
jervis customers report "MERCOS" --ia               # texto do relatório executivo redigido pela IA
jervis customers link "MERCOS" acronis --products "Acronis EDR Security; Acronis Advanced Management" --contracted 169
```

Cada execução gera, em `output\clientes\<cliente>\<data-hora>\`, três produtos:

| Arquivo | Conteúdo |
|---|---|
| `relatorio_mensal.pdf` / `.html` (+ `.xlsx`, `.csv`) | Relatório Mensal no padrão de apresentação (slides 16:9) |
| `relatorio_executivo.pdf` / `.html` | Relatório Executivo (documento A4): sumário, painel de indicadores, pontos de atenção, recomendações priorizadas, evolução mensal, acompanhamento das recomendações anteriores e considerações finais |
| `resumo.md` | Resumo em Markdown (contexto, métricas e anomalias por área, follow-up) com a seção "Insumo para a IA" |
| `metricas.json` | Indicadores da execução: base da evolução e do acompanhamento no mês seguinte |

- **Mês em andamento:** o título mostra "(até DD/MM)". Na evolução, totais acumulados (incidentes, bloqueios,
  falhas de patch, alarmes) não são comparados com um mês fechado; só a situação atual (desprotegidos,
  vulnerabilidades, offline...). A comparação usa a execução mais recente de um mês anterior do mesmo cliente.
- **Indicadores do Acronis** (proteção, ameaças, táticas MITRE, vulnerabilidades, atualizações faltantes, patches,
  sessões remotas, resumo de proteção) vêm da **API interna do console**, que não é documentada pela Acronis e
  pode mudar sem aviso. Se uma leitura falhar, o indicador fica fora do relatório (com aviso em "Limitações da
  coleta"); nunca é estimado. Incidentes de EDR vêm da API pública (MDR).
- **`--ia`** (opcional): a API do Claude redige o sumário, os pontos de atenção e as considerações finais a partir
  do `resumo.md`. O texto só é aceito se todo número citado existir nos dados; senão (ou sem chave/conexão) o
  relatório sai com o texto padrão e o motivo aparece no terminal. Painéis, tabelas e recomendações vêm sempre dos
  dados. Chave no cofre: `jervis ia set-key` (removível com `jervis ia delete-key`); alternativa: variável
  `ANTHROPIC_API_KEY`. O resumo enviado contém nomes de máquinas e usuários do cliente.
- HTML e PDF do Relatório Mensal seguem o padrão de apresentação da Contego (páginas 16:9): capa com os serviços, destaques, uma
  página por serviço com indicadores, gráfico e observações, recomendações priorizadas e anexo. Excel e CSV
  trazem a lista completa.
- Observações e recomendações são calculadas dos dados (backup, máquinas offline, incidentes, disponibilidade,
  problemas antigos, volume de alarmes...).
- **Notas da equipe** (destaques do mês, notas técnicas, melhorias, recomendações e observações extras): arquivo
  YAML em `notas/<cliente>/<AAAA-MM>.yaml` (mensal) ou `notas/<cliente>/notas.yaml`, lido automaticamente; modelo
  em `src/jervis/templates/notas.exemplo.yaml`. A pasta `notas/` fica fora do Git.
- No Acronis, a API devolve os alertas **ativos**: num mês já encerrado, aparecem só os que continuam abertos.

### Todos os clientes da plataforma

```powershell
jervis services clients acronis                     # clientes do Acronis e a situação de cada um no cadastro
jervis services clients acronis --import            # cadastra os que faltam e cria o vínculo (pede confirmação)
jervis services clients zabbix --only "MERCOS"      # no Zabbix, cada cliente é um grupo de hosts: importe só os de cliente
jervis customers report --all                       # relatório de todos os clientes vinculados, um após o outro
```

- Situações: **vinculado** (o nome na plataforma do vínculo existe nela), **cadastrado, sem vínculo** (há um
  cliente com o mesmo nome no cadastro), **não cadastrado** e **nome repetido no cadastro** (não é importado:
  vincule pelo id). Vínculos cujo nome não existe mais na plataforma aparecem como "Atenção".
- A importação usa o nome da plataforma como nome do cliente. Produtos, dispositivos contratados e id do Desk
  Manager se completam depois com `jervis customers link` / `customers update`.
- `--all` gera os três produtos de cada cliente e termina com um resumo (sucesso, parcial ou falha e a pasta). A
  falha de um cliente não interrompe os demais. Os clientes rodam um após o outro (coleta e PDFs de cada um).

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
