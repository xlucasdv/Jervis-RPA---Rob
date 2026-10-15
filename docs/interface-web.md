# Interface web da equipe

A interface é um site interno onde a equipe revisa os relatórios do fechamento mensal. Pelo navegador, dá para ver o
que foi gerado, abrir os PDFs, aprovar, rejeitar e pedir uma nova geração.

- **Contas:** são próprias do Jervis. O administrador cria o login de cada colega na página **Usuários**, e o
  Jervis gera uma senha temporária. No primeiro acesso, a pessoa cria a senha dela e configura o app autenticador
  (código de 6 dígitos no celular).
- **Perfis:**

  | Perfil | Pode |
  |---|---|
  | `leitura` | ver os relatórios e abrir os arquivos |
  | `revisor` | também aprovar (um ou vários de uma vez) e rejeitar com motivo |
  | `admin` | também gerar de novo, voltar uma revisão para pendente e administrar as contas |

- **Proteções:**
  - acesso só pela rede interna ou pela VPN, sempre por HTTPS;
  - senhas guardadas só como hash (scrypt);
  - a conta é bloqueada por 15 minutos depois de 5 tentativas erradas, e cada computador tem um limite de
    tentativas;
  - trocar a senha, suspender a conta ou mudar o perfil encerra as sessões abertas da pessoa.
- **Registro:** cada login, aprovação, rejeição, arquivo aberto e mudança de conta vai para a trilha de auditoria
  (`jervis audit`), com o e-mail da pessoa e o IP. Senhas nunca são registradas.

## 1. Criar a sua conta de admin (uma vez)

No PowerShell, na pasta do Jervis:

```powershell
jervis web users add seu.email@contego.com.br --name "Seu Nome" --role admin
```

O comando mostra uma **senha temporária**, só nesse terminal. Ela vale até o primeiro login. Confira se está tudo
pronto:

```powershell
jervis web check
```

## 2. Liberar a porta no firewall (administrador do Windows, uma vez)

Num PowerShell **como administrador**, neste PC:

```powershell
New-NetFirewallRule -DisplayName "Jervis3000 interface web" -Direction Inbound -Protocol TCP -LocalPort 8443 `
  -Profile Domain,Private -RemoteAddress 10.0.0.0/8 -Action Allow
```

Ajuste `-RemoteAddress` para as faixas do escritório e da VPN. Elas devem ser as mesmas de `allowed_networks`.

Sem essa regra, a interface funciona só neste PC.

## 3. Subir a interface

Com o Docker Desktop (MySQL) rodando:

```powershell
jervis web serve
```

Deixe o terminal aberto. `Ctrl+C` desliga a interface. Endereço: **https://ctgnotcwb010:8443**.

## 4. Primeiro acesso

1. Abra o endereço e entre com o e-mail e a senha temporária.
2. Crie a sua senha. Ela precisa ter ao menos 12 caracteres, e uma frase curta funciona bem.
3. No celular, instale o Microsoft Authenticator ou o Google Authenticator, leia o QR code e digite o código.

Nos próximos acessos, o Jervis pede a senha e o código do app.

## 5. Criar as contas da equipe

Na interface, vá em **Usuários > Nova conta** e preencha nome, e-mail e perfil. O Jervis mostra a senha temporária
uma vez só. Passe para a pessoa por um canal privado, como uma conversa direta no Teams ou pessoalmente. No primeiro
login, ela faz os passos 2 e 3 acima.

Na mesma página:

| Botão | Quando usar |
|---|---|
| **Nova senha** | A pessoa esqueceu a senha ou bloqueou a conta. Gera outra senha temporária. |
| **Redefinir app** | A pessoa trocou de celular. Ela configura o app de novo no próximo login. |
| **Suspender / Reativar** | A pessoa saiu da equipe. Ela é desconectada na hora. |
| **Perfil** | Escolha na lista. A mudança vale na hora. |

Você não pode suspender nem rebaixar a sua própria conta, e o Jervis nunca fica sem um admin ativo. Se você mesmo
perder o acesso, pelo terminal deste PC:

```powershell
jervis web users reset-password seu.email@contego.com.br
jervis web users reset-mfa seu.email@contego.com.br
jervis web users list
```

## 6. Certificado nos computadores da equipe

O certificado HTTPS é emitido por uma autoridade interna do Jervis (`config/web/jervis-ca.cer`). Sem ela instalada,
o navegador mostra o aviso "sua conexão não é particular". Em cada computador da equipe, instale o arquivo uma vez:

1. Dê dois cliques no arquivo e clique em **Instalar certificado**.
2. Escolha **Máquina local**.
3. Escolha **Colocar todos os certificados no repositório a seguir** e depois **Autoridades de Certificação Raiz
   Confiáveis**.

Outra opção é distribuir por política de grupo (GPO).

Só o `.cer` é distribuído. As chaves (`*.key`) nunca saem deste PC, e a pasta `config/web` não vai para o git.

O certificado do servidor vale cerca de 13 meses, e `jervis web check` mostra quantos dias faltam. Para renovar,
rode `jervis web cert --force`; ninguém precisa reinstalar nada.

## Configuração

Seção `web` de `config/platforms.yaml`:

```yaml
web:
  public_url: https://ctgnotcwb010:8443   # endereço que a equipe abre
  mfa: todos                              # código do app autenticador: todos | admin | nenhum
  port: 8443
  # allowed_networks: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8]
  # session_hours: 8                      # horas até pedir o login de novo
```

A chave do app autenticador de cada pessoa fica criptografada no banco, com a mesma chave que protege os segredos
MFA das plataformas (`jervis db generate-key`). Guarde uma cópia segura dessa chave: sem ela, todos precisam configurar o
app de novo.

## Neste PC

A interface fica acessível enquanto este notebook estiver ligado, na rede e com o terminal aberto. Para uso
contínuo, o ideal é levar o Jervis para um servidor ou VM sempre ligados. Nesse caso, mude o `public_url` e rode
`jervis web cert --force`.

## Problemas comuns

| O que aparece | O que fazer |
|---|---|
| "E-mail ou senha incorretos" | Confira o e-mail. Esqueceu a senha? Um admin usa **Nova senha** |
| "Conta bloqueada por tentativas erradas" | Espere 15 minutos, ou um admin usa **Nova senha** (também desbloqueia) |
| "Código incorreto ou expirado" | Confira se o horário do celular está automático. Trocou de celular? **Redefinir app** |
| "Muitas tentativas erradas a partir deste computador" | Espere 15 minutos |
| "Acesso negado" sem nem ver o login | O IP da pessoa está fora de `allowed_networks` (VPN em outra faixa?) |
| Aviso de site não seguro no navegador | Instale `jervis-ca.cer` naquele computador (passo 6) |
| A página não abre de outro computador | Firewall (passo 2), ou o nome `ctgnotcwb010` não resolve na rede: teste com o IP |
