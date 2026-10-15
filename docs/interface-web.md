# Interface web da equipe

A interface é um site interno onde a equipe revisa os relatórios do fechamento mensal. Pelo navegador, dá para ver o
que foi gerado, abrir os PDFs, aprovar, rejeitar e pedir uma nova geração.

- **Entrada:** com a conta Microsoft 365 de cada pessoa. Só entra quem tem acesso liberado no Jervis.
- **Perfis:**

  | Perfil | Pode |
  |---|---|
  | `leitura` | ver os relatórios e abrir os arquivos |
  | `revisor` | também aprovar (um ou vários de uma vez) e rejeitar com motivo |
  | `admin` | também gerar de novo um relatório e voltar uma revisão para pendente |

- **Acesso:** só pela rede interna ou pela VPN, sempre por HTTPS. Conexões de fora dessas redes são recusadas.
- **Registro:** cada login, aprovação, rejeição e arquivo aberto vai para a trilha de auditoria (`jervis audit`),
  com o e-mail da pessoa e o IP. Na revisão, fica gravado quem aprovou.

O Jervis só pede à Microsoft a identificação da pessoa (nome e e-mail). Ele não recebe acesso a e-mails, arquivos
nem ao Teams.

## 1. Registrar o Jervis no Entra ID (administrador do Microsoft 365)

Faça uma vez só.

1. Abra o [Centro de administração do Microsoft Entra](https://entra.microsoft.com) e vá em
   **Aplicativos > Registros de aplicativo > Novo registro**.
2. Preencha:
   - **Nome:** `Jervis3000`.
   - **Tipos de conta com suporte:** *Somente contas deste diretório organizacional* (um único locatário).
   - **URI de Redirecionamento:** plataforma **Web**, endereço `https://<máquina>:8443/auth/callback`.
     O endereço exato aparece em `jervis web check`; neste PC é `https://ctgnotcwb010:8443/auth/callback`.
3. Na página do aplicativo, em **Visão geral**, copie:
   - **ID do aplicativo (cliente)**, que vai em `client_id`;
   - **ID do diretório (locatário)**, que vai em `tenant_id`.
4. Em **Certificados e segredos > Novo segredo do cliente**, crie um segredo com validade de 12 ou 24 meses. Copie
   o **Valor** na hora, porque ele aparece só uma vez. Ele vai para o cofre no passo 2, nunca para arquivos nem
   para o chat.
5. **Permissões de API:** deixe só a padrão (`User.Read`, delegada). O Jervis não precisa de mais nada.
6. **Opcional, recomendado:** em **Aplicativos empresariais > Jervis3000 > Propriedades**, ligue
   **Atribuição obrigatória**. Depois, em **Usuários e grupos**, inclua só a equipe. Assim a própria Microsoft já
   barra quem não for da equipe, antes mesmo do Jervis.

Anote quando o segredo vence. Antes disso, crie um novo segredo e repita o passo 2.

## 2. Configurar o Jervis

Na seção `web` de `config/platforms.yaml`:

```yaml
web:
  public_url: https://ctgnotcwb010:8443
  tenant_id: <ID do diretório>
  client_id: <ID do aplicativo>
  port: 8443
```

Depois, no terminal:

```powershell
jervis web set-secret                                   # cola o Valor do segredo (não aparece na tela)
jervis web cert                                         # certificado HTTPS desta máquina (já feito neste PC)
jervis web users add voce@contego.com.br --role admin   # o seu acesso
jervis web check                                        # tudo [ok]?
```

## 3. Liberar a equipe

```powershell
jervis web users add maria@contego.com.br --role revisor
jervis web users add joao@contego.com.br --role leitura
jervis web users list
jervis web users role joao@contego.com.br revisor       # muda o perfil
jervis web users disable maria@contego.com.br           # suspende na hora, mesmo com a sessão aberta
```

O e-mail é o da conta Microsoft 365, o mesmo do Teams. No primeiro login, o Jervis grava o ID da conta no Entra.
Se o mesmo e-mail for reaproveitado depois para outra pessoa, ela não herda o acesso.

## 4. Certificado nos computadores da equipe

O certificado HTTPS é emitido por uma autoridade interna do Jervis (`config/web/jervis-ca.cer`). Em cada computador
da equipe, instale esse arquivo uma vez:

1. Dê dois cliques no arquivo e clique em **Instalar certificado**.
2. Escolha **Máquina local**.
3. Escolha **Colocar todos os certificados no repositório a seguir** e depois **Autoridades de Certificação Raiz
   Confiáveis**.

Outra opção é distribuir o arquivo por política de grupo (GPO). Sem ele, o navegador mostra o aviso "sua conexão
não é particular".

Na pasta `config/web` também ficam as chaves privadas (`*.key`). Elas nunca saem desta máquina: só o `.cer` é
distribuído. A pasta não vai para o git.

O certificado do servidor vale cerca de 13 meses, e `jervis web check` mostra quantos dias faltam. Para renovar,
rode `jervis web cert --force`. A autoridade interna continua a mesma, então ninguém precisa reinstalar nada.

## 5. Liberar a porta no firewall (administrador do Windows)

Num PowerShell **como administrador**, neste PC:

```powershell
New-NetFirewallRule -DisplayName "Jervis3000 interface web" -Direction Inbound -Protocol TCP -LocalPort 8443 `
  -Profile Domain,Private -RemoteAddress 10.0.0.0/8 -Action Allow
```

Ajuste `-RemoteAddress` para as faixas do escritório e da VPN. Elas devem ser as mesmas de `allowed_networks`.

## 6. Subir a interface

```powershell
jervis web serve
```

A equipe abre `https://ctgnotcwb010:8443` no navegador. A interface fica no ar enquanto o terminal estiver aberto:
`Ctrl+C` para. O Docker (MySQL) precisa estar rodando.

Neste PC, a interface só fica acessível enquanto ele estiver ligado e na rede. Para uso contínuo, o ideal é levar o
Jervis para um servidor ou VM sempre ligados. A configuração é a mesma: muda só o `public_url`, e o endereço de
retorno precisa ser atualizado no Entra ID.

## Problemas comuns

| O que aparece | O que fazer |
|---|---|
| "Interface não configurada" | Preencha `tenant_id` e `client_id` na seção `web` |
| "Login indisponível: segredo não cadastrado" | `jervis web set-secret` |
| A Microsoft mostra erro `AADSTS50011` (endereço de retorno) | O endereço cadastrado no Entra ID tem que ser exatamente o de `jervis web check` |
| "Acesso ainda não liberado" | `jervis web users add <e-mail> --role ...` |
| "Acesso negado" sem nem chegar ao login | O IP da pessoa está fora de `allowed_networks` (VPN em outra faixa?) |
| Aviso de site não seguro no navegador | Instale `jervis-ca.cer` naquele computador (passo 4) |
| A página não abre de outro computador | Firewall (passo 5), ou o nome `ctgnotcwb010` não resolve na rede: teste com o IP |
