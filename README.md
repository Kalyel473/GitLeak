# GitLeak Hunter BR

Ferramenta em Bash puro que descobre repositórios `.git` expostos publicamente,
reconstrói o histórico completo do repositório (sem precisar de Git no alvo) e
varre **todos os commits  inclusive os "apagados" — atrás de secrets vazados.



## O problema

Repositórios `.git` acabam expostos em produção com uma frequência assustadora:
deploy feito com `git clone` direto no servidor web, sem remover a pasta `.git` do
*document root*. Quem encontra isso baixa o **histórico inteiro** do projeto.

E aqui está o pulo do gato: **deletar um arquivo e commitar de novo NÃO apaga nada
do histórico do Git** — só esconde do estado atual (`HEAD`). Aquele `.env` que o dev
commitou por engano e "removeu" no commit seguinte continua lá, para sempre,
recuperável por qualquer um com acesso ao `.git`.

A GitLeak Hunter BR automatiza esse achado de ponta a ponta e entrega uma prova de
conceito pronta, no formato clássico de bug bounty (baixo esforço, alto impacto).

---

## Como funciona (4 módulos)

1. **Detecção** — testa `GET /.git/HEAD` e confirma pelo **conteúdo esperado**
   (`ref: refs/heads/...`), não só pelo HTTP 200 (evita falso positivo de página
   404 customizada). Faz confirmação cruzada com `/.git/config`, `/.git/index`
   (assinatura `DIRC`) e `/.git/logs/HEAD`.
2. **Reconstrução** — baixa `index`, refs, packfiles (`objects/info/packs`) e os
   objects soltos, seguindo recursivamente os SHAs a partir de `HEAD`
   (`commit → tree → parent → blobs`). Usa o **Git da sua máquina** (o alvo não
   precisa de Git) para montar um `.git` funcional local. Ao final,
   `git log --all` e `git clone` funcionam normalmente sobre o repo reconstruído.
3. **Varredura de secrets** — roda sobre `git log --all` (todas as branches, inclusive
   commits órfãos/dangling recuperados). Para cada commit, aplica regex contra
   padrões de secrets (AWS keys, chaves privadas, JWT, connection strings de banco,
   `API_KEY=`, `SECRET=`, `PASSWORD=`, `.env` completo, etc.). Marca especialmente
   arquivos que **existiam em commits antigos e foram deletados depois** — os
   achados mais valiosos.
4. **Relatório** — consolida os achados com arquivo, secret (mascarado), hash do
   commit, data, autor, e se o arquivo ainda existe no `HEAD` ou só no histórico.
   Exporta em **Markdown** e **JSON**, com resumo executivo e nota de exposição 0–10.

---

## Instalação

Não há o que instalar além das ferramentas padrão que já vêm em qualquer
Kali/Debian/Ubuntu:

```bash
sudo apt install curl git   # grep, awk e sed já vêm no sistema
chmod +x gitleak_hunter_br.sh
```

Compatível com **Linux** e **WSL** (bash 4+). Se o `git` não estiver instalado, os
módulos de reconstrução e demo são desativados com aviso (degradação graciosa).

---

## Uso

```bash
# Alvo único
./gitleak_hunter_br.sh -t alvo.com.br

# Lista de alvos (um por linha; linhas com # são comentários), JSON e rate limit
./gitleak_hunter_br.sh -f lista_alvos.txt --output json --delay 2

# Modo demonstração: cria um repo .git sintético local com secrets fake e roda
# a análise completa — SEM internet e SEM alvo real (ideal para gravar em vídeo)
./gitleak_hunter_br.sh --demo
```

### Flags

| Flag | Descrição |
|------|-----------|
| `-t <alvo>` | Alvo único (domínio ou URL) |
| `-f <arquivo>` | Lista de alvos, um por linha |
| `--output <fmt>` | Formato do relatório: `markdown` (padrão) ou `json` |
| `--delay <seg>` | Pausa entre requests (rate limiting). Padrão: `0` |
| `--demo` | Repositório `.git` sintético local com secrets fake |
| `--no-confirm` | Pula o gate de autorização (**só** para pipeline já autorizado) |
| `-h`, `--help` | Ajuda |

### Saída

Relatórios são salvos em `reports/<alvo>_<timestamp>.{md,json}`.

Exemplo de achado (Markdown):

```markdown
### 🔴 CRÍTICO — AWS Access Key

- **Arquivo:** `config/aws_credentials.py`
- **Status atual:** removido do HEAD (existe só no histórico)
- **Commit:** `a3f9c21` — "remove hardcoded creds"
- **Autor:** dev@empresa.com.br
- **Data:** 2019-03-14
- **Secret (mascarado):** `AKIA****************MPLE`
- **Como reproduzir:** `git show a3f9c21:config/aws_credentials.py`
```

O relatório termina com um **resumo executivo**: total de secrets por severidade
(Crítico/Alto/Médio), total de commits analisados, tempo de execução e a **nota de
exposição (0–10)**.

---

## Segredos no terminal x no arquivo

> ⚠️ **Importante.** No **terminal**, os secrets são sempre **mascarados**
> (`AKIA****************MPLE`). Já os **arquivos de relatório** em `reports/`
> contêm o **secret completo**, porque isso é necessário para o PoC/reprodução.
> Trate esses arquivos como **confidenciais**: eles são credenciais reais do alvo.
> Nunca os versione, envie por canais inseguros ou deixe em máquina compartilhada.

---

## Segurança da própria ferramenta

- **Sanitização de entrada:** todo domínio/URL passa por uma whitelist estrita antes
  de ir para o `curl`, evitando injeção de comando via nome de alvo malicioso.
- **Rate limiting** configurável (`--delay`) para não parecer um ataque de força
  bruta/DoS contra o alvo.
- **100% local:** sem telemetria, sem callback externo. Depois do download dos
  objects, tudo roda na sua máquina.
- **Mascaramento** de secrets no output de tela.

---

## Ética e aspecto legal

Esta ferramenta é para **teste de segurança autorizado**, bug bounty dentro de
escopo e fins educacionais. Antes de qualquer varredura ativa contra um alvo, o
script exige **confirmação explícita de autorização** (`[s/N]`).

- **Lei 12.737/2012 (Lei Carolina Dieckmann):** invadir dispositivo informático
  alheio, conectado ou não à rede, sem autorização expressa ou tácita do titular,
  é **crime** no Brasil.
- **LGPD (Lei 13.709/2018):** dados pessoais eventualmente encontrados durante um
  teste estão sujeitos à Lei Geral de Proteção de Dados; trate-os conforme a lei e
  a política de divulgação responsável do programa.

Use **somente** contra sistemas para os quais você tem autorização por escrito
(programa de bug bounty com escopo definido, contrato de pentest, ou seu próprio
laboratório). O autor e o canal **não se responsabilizam** por uso indevido.

---

## Critérios de aceite (validados)

- [x] Detecta `.git` exposto confirmando pelo **conteúdo** (não só HTTP 200)
- [x] Reconstrói o repositório e o `git log --all` resultante bate 100% com o original
- [x] `git clone` local funciona sobre o repo reconstruído
- [x] Encontra secrets em commits antigos, **inclusive os "removidos"** depois
- [x] Modo `--demo` roda do zero ao fim **sem internet** e **sem alvo real**
- [x] Gate de autorização não pode ser pulado sem `--no-confirm` explícito
- [x] Roda em menos de 2 minutos contra um repositório de teste típico
