# Solução de problemas

## Por onde começar

1. `jervis status` e `jervis runs show` — o que falhou e em qual etapa.
2. `output/<execução>/execucao.log` — o progresso daquela execução; `logs/jervis.log` — detalhes técnicos
   (filtre pelo id da execução).
3. `jervis check <plataforma> --headed --screenshots` — reproduz login e páginas vendo o navegador, sem coletar.
4. Ative `screenshot_on_failure: true` em `settings` para guardar a tela no momento das próximas falhas.

Toda falha registrada tem uma **categoria**. Procure-a abaixo.

## `autenticacao` — falha de login

| Mensagem | Causa provável | O que fazer |
|---|---|---|
| `Acesso negado pela plataforma: "..."` | Usuário/senha errados, conta bloqueada ou expirada | Teste o login manualmente no navegador; atualize com `jervis credentials set <plataforma>` |
| `Nenhuma credencial cadastrada` (`configuracao`) | Credencial não cadastrada **para este usuário do Windows/ambiente** | `jervis [--env X] credentials set <plataforma>` com o mesmo usuário que executa a coleta/tarefa |
| `MFA ... segredo não foi cadastrado` | `mfa: totp` sem segredo | `jervis credentials set sophos --totp` |
| `Código MFA recusado` | Relógio da máquina atrasado/adiantado, ou segredo errado | Sincronize o relógio (`w32tm /resync`); recadastre o segredo |
| `solicitou código MFA, mas a execução não é interativa` | `mfa: prompt` em execução agendada | Use `mfa: totp` |
| `Tempo esgotado aguardando a tela de login` | URL errada, página de login mudou, ou SSO redirecionando | Confira a URL no navegador; ajuste `selectors.username`/`password`/`submit` ([configuração](configuracao.md#seletores-de-login-selectors)) |
| `Tempo esgotado aguardando a resposta do login` | Login funcionou, mas a ferramenta não reconheceu a página seguinte | Ajuste `selectors.success` (elemento visível após o login) ou `success_url` |
| `A plataforma voltou para a tela de login` (durante a coleta) | Sessão expirou ou o usuário não tem acesso àquela área | Rode de novo; se persistir, verifique as permissões do usuário de serviço na página indicada |

## `interface_alterada` — a página mudou

Mensagens: `Coluna(s) obrigatória(s) não encontrada(s): ... Colunas na página: ...`, `Tabela não encontrada`,
`Página não encontrada (HTTP 404)`.

1. Rode `jervis check <plataforma>`: ele lista as **colunas que existem na tela** para cada página.
2. Se a coluna só mudou de nome (ex.: "Integridade" → "Saúde do agente"), acrescente o rótulo novo:
   ```yaml
   params:
     dispositivos:
       columns:
         status_agente: ["Saúde do agente", "Integridade", "Health"]
   ```
   Coluna sem título (só ícone)? Use a posição: `severidade: ["#1"]`.
3. Se a página mudou de endereço (HTTP 404 ou "Tabela não encontrada"), abra a plataforma no navegador, navegue
   até a lista e copie o caminho para `params.<conjunto>.pages`.
4. Se a lista não é uma `<table>` comum, ajuste os seletores em `params.<conjunto>.table` (`rows`, `cells`,
   `headers`, `next_page`, `loading`, `empty`).
5. Confirme com `jervis check` e reprocesse com `jervis retry`.

Avisos `Coluna(s) não encontrada(s) na tela (ficarão vazias)` não impedem a coleta, mas indicam campos que o
relatório mostrará vazios: trate da mesma forma.

## `tempo_esgotado`

A página não terminou de carregar dentro de `collect_timeout` (ou `params.timeout`). Plataformas lentas ou listas
grandes: aumente o tempo daquela plataforma (`params.timeout: 90`). Já há uma nova tentativa automática
(`params.retries`). Se acontece sempre na mesma página, pode ser um indicador de carregamento que nunca some:
veja a captura de tela e ajuste `params.<conjunto>.table.loading`.

## `indisponibilidade`

`Plataforma inacessível ... ERR_NAME_NOT_RESOLVED / ERR_CONNECTION_REFUSED`, `HTTP 5xx`: problema de rede, DNS,
proxy ou da própria plataforma. Teste com `jervis platforms list --check` e no navegador da mesma máquina. Em
redes com proxy autenticado, o navegador usado pela ferramenta segue a configuração de proxy do Windows.

## `dados_incompletos`

`hosts: 3 registro(s), 95% a menos que na última coleta bem-sucedida (60)`. Não houve erro de tela, mas veio bem
menos dado que o normal. Causas comuns: permissão do usuário de serviço reduzida, filtro salvo no perfil do usuário
(as listas respeitam filtros e "linhas por página" do perfil), mudança real no ambiente. Confira entrando na
plataforma com o usuário de serviço. Se a queda for legítima, a próxima coleta bem-sucedida passa a ser a nova
referência. O limite é `settings.incomplete_drop_pct`.

## Navegador e driver

| Sintoma | O que fazer |
|---|---|
| `Uma política de Controle de Aplicativos bloqueou este arquivo` / `Unable to obtain driver` | Use um driver aprovado em `settings.driver_path` ([instalação](instalacao.md#driver-do-navegador-em-máquinas-corporativas)) |
| `This version of Microsoft Edge WebDriver only supports Microsoft Edge version N` | O Edge foi atualizado: baixe o driver da nova versão |
| `Driver não encontrado em settings.driver_path` | Caminho errado ou arquivo removido |
| Relatório PDF `não gerado` | O PDF usa o mesmo navegador: resolva o driver; os outros formatos são gerados normalmente. Gere depois com `jervis report --formats pdf` |

## Agendamento

| Sintoma | O que fazer |
|---|---|
| `jervis schedule list` mostra "NO WINDOWS: não" | `jervis schedule install` |
| A tarefa não roda com a sessão desconectada | Propriedades da tarefa → "Executar estando o usuário conectado ou não" |
| Resultado da última execução `0x1` | Erro de configuração: veja `logs/agendamento-<nome>.log` |
| Resultado `0x2` / `0x3` | Coleta parcial / falhou: `jervis runs show` |
| `Já existe uma coleta em andamento` | Outra execução estava rodando; o agendamento seguinte coleta normalmente |
| Mudou a pasta do projeto ou o Python | `jervis schedule install` de novo (as tarefas guardam o caminho) |
| Credencial "não cadastrada" só na tarefa | A tarefa roda com outro usuário do Windows: cadastre as credenciais com esse usuário |

## Execuções e histórico

- **`INTERROMPIDA` em `jervis runs`**: o processo terminou no meio (máquina desligada, processo encerrado).
  Os resultados das plataformas já concluídas estão salvos; complete com `jervis retry <pasta>`.
- **Execução com estado `erro`**: falha inesperada da ferramenta. O traceback está em `logs/jervis.log`
  (filtre pelo id da execução); reporte ao responsável pela ferramenta.
- **`jervis audit --verify` indica alteração**: a trilha foi editada depois do registro. Preserve o arquivo e
  investigue quem tem acesso de escrita à pasta `logs/`.

## Notificações

`jervis notify test` envia uma mensagem de teste e mostra o erro de cada canal. `SMTPAuthenticationError`: senha
do SMTP (`jervis notify set-smtp-password`) ou usuário errados. Timeout: porta/servidor errados ou bloqueados.
Webhook `HTTP 4xx`: URL inválida ou fluxo do Teams desativado (`jervis notify set-webhook`).

## Cofre de credenciais

`Cofre de senhas do sistema indisponível`: o Gerenciador de Credenciais não está acessível (ex.: serviço sem
perfil de usuário carregado). Alternativa: variáveis de ambiente `JERVIS_<PLATAFORMA>_USERNAME/_PASSWORD`.
