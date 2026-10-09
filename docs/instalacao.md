# Instalação

## Pré-requisitos

| Item | Observação |
|---|---|
| Windows 10/11 ou Windows Server | Também funciona em Linux/macOS, mas o agendamento integrado e o cofre de credenciais foram validados no Windows |
| Python 3.11 ou superior | `py -0` lista as versões instaladas |
| Microsoft Edge | Navegador padrão. Chrome e Firefox também são suportados (`settings.browser`) |
| Driver do navegador | Baixado automaticamente pelo Selenium Manager, exceto em máquinas com política de controle de aplicativos ou sem internet (veja abaixo) |
| Acesso de rede às plataformas | HTTPS para o Sophos Central, a Acronis Cyber Protect Cloud e o Zabbix |
| Usuário de serviço em cada plataforma | Somente leitura é suficiente. Para o Sophos Central, com MFA por aplicativo autenticador (TOTP) |

## Passo a passo

As dependências são gerenciadas com **uv** (`pyproject.toml` + `uv.lock`, versões travadas):

```powershell
cd C:\Jervis3000
py -3.12 -m pip install --user uv          # uma vez por máquina (fora do ambiente virtual)
py -3.12 -m uv sync                        # cria/atualiza o .venv com as versões do uv.lock (inclui o grupo dev)
.venv\Scripts\python -m jervis --version
```

- Adicionar uma dependência: `py -3.12 -m uv add <pacote>` (atualiza `pyproject.toml` e `uv.lock`).
- Use `py -3.12 -m uv`, e não `uv` direto, se o executável não estiver no PATH.

Use sempre `.venv\Scripts\python -m jervis ...`. O executável `jervis.exe` gerado pelo pip pode ser
bloqueado pela política de controle de aplicativos do Windows; o `python.exe` do ambiente virtual não é.

## Driver do navegador em máquinas corporativas

Por padrão o Selenium baixa o driver na primeira execução usando o `selenium-manager.exe`. Em máquinas com
**Controle de Aplicativos do Windows (App Control/WDAC)**, esse executável é bloqueado ("Uma política de
Controle de Aplicativos bloqueou este arquivo"). Nesse caso, com o Edge (recomendado):

```powershell
.venv\Scripts\python -m jervis driver update --auto
```

- Descobre a versão do Edge instalado, baixa o `msedgedriver.exe` correspondente de
  `msedgedriver.microsoft.com` para `drivers\msedgedriver.exe` e grava `settings.driver_path`.
- O arquivo só substitui o driver atual depois de conferidas a **assinatura digital da Microsoft** e a versão.
- `--auto` liga `settings.driver_auto_update`: antes de cada coleta, verificação e login, a ferramenta confere
  a versão e baixa o driver novo quando o Edge se atualiza (uma versão principal por mês). Se não conseguir
  (sem internet, proxy), avisa e segue com o driver atual.
- `jervis driver status` mostra as versões do Edge e do driver e se são compatíveis.
- A pasta `drivers\` precisa ser gravável pelo usuário que roda as coletas agendadas.

Sem acesso a `msedgedriver.microsoft.com`, faça manualmente:

1. Descubra a versão do Edge: `(Get-Item "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe").VersionInfo.ProductVersion`
2. Baixe o `msedgedriver.exe` da mesma versão em https://developer.microsoft.com/microsoft-edge/tools/webdriver/
   (o arquivo é assinado pela Microsoft e costuma ser permitido pela política).
3. Guarde-o em uma pasta aprovada pela TI (ex.: `C:\Ferramentas\drivers\msedgedriver.exe`) e informe em
   `settings.driver_path` no arquivo de configuração.
4. Quando o Edge for atualizado, atualize também o driver (o erro "session not created: This version of
   Microsoft Edge WebDriver only supports..." indica versões diferentes).

## Banco de dados e fila (MySQL e RabbitMQ)

Os dois rodam em contêineres Docker (`docker-compose.yml`), acessíveis só desta máquina. As senhas não ficam em
arquivo: são definidas no terminal antes de subir.

```powershell
$env:JERVIS_MYSQL_ROOT_PASSWORD = Read-Host "Senha root do MySQL" -MaskInput
$env:JERVIS_MYSQL_PASSWORD      = Read-Host "Senha do usuário jervis no MySQL" -MaskInput
$env:JERVIS_RABBITMQ_PASSWORD   = Read-Host "Senha do usuário jervis no RabbitMQ" -MaskInput
docker compose up -d                                   # Docker Desktop precisa estar aberto
```

Depois, uma vez:

```powershell
.venv\Scripts\python -m jervis db set-credentials --username jervis   # a mesma senha de JERVIS_MYSQL_PASSWORD
.venv\Scripts\python -m jervis db generate-key                        # chave que criptografa as chaves MFA
.venv\Scripts\python -m jervis db init                                # cria as tabelas (também é automático)
.venv\Scripts\python -m jervis db status
```

Inclua a seção `database` no arquivo de configuração ([configuração](configuracao.md#banco-de-dados-database)).
Faça uma cópia segura da chave gerada por `db generate-key`: sem ela, as chaves MFA gravadas no banco não podem
ser lidas.

## Primeira configuração

```powershell
.venv\Scripts\python -m jervis init                                   # cria config\platforms.yaml
.venv\Scripts\python -m jervis platforms set-url zabbix https://zabbix.empresa.com.br/index.php
.venv\Scripts\python -m jervis credentials set zabbix --username svc_coleta
.venv\Scripts\python -m jervis platforms enable zabbix
.venv\Scripts\python -m jervis check zabbix --headed                  # valida login, páginas e colunas
.venv\Scripts\python -m jervis collect zabbix
```

Repita para a Sophos (`jervis credentials set sophos --totp`) e a Acronis. O `jervis check` é o passo mais
importante numa instalação nova: ele mostra se os endereços das páginas e os rótulos das colunas configurados
batem com a versão de cada plataforma, sem coletar dados. Veja [Solução de problemas](solucao-de-problemas.md)
se algo falhar.

## Atualização da ferramenta

```powershell
cd C:\Jervis3000
py -3.12 -m uv sync                                 # após atualizar o código-fonte
.venv\Scripts\python -m pytest -q                   # confere se tudo continua funcionando
.venv\Scripts\python -m jervis check                # confere as plataformas reais
```

Agendamentos registrados no Windows apontam para o `python.exe` do ambiente virtual: se a pasta do projeto ou
o ambiente virtual mudarem de lugar, execute `jervis schedule install` de novo.
