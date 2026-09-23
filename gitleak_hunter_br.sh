#!/usr/bin/env bash

set -o pipefail

# ------------------------------------------------------------------------------
# Cores ANSI puras (sem tput / terminfo — mais portável)
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''
  C_YELLOW=''; C_BLUE=''; C_MAGENTA=''; C_CYAN=''
fi

# ------------------------------------------------------------------------------
# Configuração / estado global
# ------------------------------------------------------------------------------
VERSION="1.0.0"
TARGET=""              # alvo único (-t)
TARGET_FILE=""         # lista de alvos (-f)
OUTPUT="markdown"      # markdown | json
DELAY="0"              # segundos entre requests (--delay)
DEMO=0                 # --demo
NO_CONFIRM=0           # --no-confirm
TIMEOUT=15             # timeout por request curl (s)
UA="Mozilla/5.0 (GitLeakHunterBR/${VERSION}; +pentest-autorizado)"
REPORTS_DIR="reports"
NOW_TS="$(date +%Y%m%d_%H%M%S)"

# Contadores globais de achados (para o resumo executivo)
COUNT_CRIT=0; COUNT_HIGH=0; COUNT_MED=0; COMMITS_ANALYZED=0

# ------------------------------------------------------------------------------
# Padrões de secrets:  nome|severidade|regex(ERE)
# Severidade: CRITICO | ALTO | MEDIO
# ------------------------------------------------------------------------------
SECRET_PATTERNS=(
  "AWS Access Key|CRITICO|AKIA[0-9A-Z]{16}"
  "Chave privada (PEM)|CRITICO|-----BEGIN( RSA| EC| OPENSSH| DSA| PGP)? ?PRIVATE KEY-----"
  "Connection string MongoDB|CRITICO|mongodb(\+srv)?://[^:@/ ]+:[^@/ ]+@[^ \"']+"
  "Connection string PostgreSQL|CRITICO|postgres(ql)?://[^:@/ ]+:[^@/ ]+@[^ \"']+"
  "Connection string MySQL|CRITICO|mysql://[^:@/ ]+:[^@/ ]+@[^ \"']+"
  "AWS Secret Key|CRITICO|aws_secret_access_key[[:space:]]*=[[:space:]]*[\"']?[A-Za-z0-9/+]{40}"
  "Google API Key|ALTO|AIza[0-9A-Za-z_-]{35}"
  "Slack Token|ALTO|xox[baprs]-[0-9A-Za-z-]{10,48}"
  "GitHub Token|ALTO|gh[pousr]_[0-9A-Za-z]{36,}"
  "JWT|ALTO|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
  "Variável API_KEY|ALTO|(API_KEY|APIKEY|API_TOKEN)[[:space:]]*[=:][[:space:]]*[\"']?[A-Za-z0-9_./+-]{8,}"
  "Variável SECRET|ALTO|(SECRET|SECRET_KEY|CLIENT_SECRET)[[:space:]]*[=:][[:space:]]*[\"']?[A-Za-z0-9_./+-]{8,}"
  "Variável PASSWORD|ALTO|(PASSWORD|PASSWD|DB_PASS(WORD)?)[[:space:]]*[=:][[:space:]]*[\"']?[^[:space:]\"']{6,}"
  "Token genérico (Bearer)|MEDIO|[Bb]earer[[:space:]]+[A-Za-z0-9._-]{16,}"
)

# ==============================================================================
# Utilitários de log (todos coloridos, sequências ANSI direto)
# ==============================================================================
log_info() { printf '%s[*]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
log_ok()   { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
log_warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
log_err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
log_crit() { printf '%s[CRÍTICO]%s %s\n' "$C_RED$C_BOLD" "$C_RESET" "$*"; }

die() { log_err "$*"; exit 1; }

# ==============================================================================
# Banner + aviso legal
# ==============================================================================
print_banner() {
  printf '%s' "$C_CYAN$C_BOLD"
  cat <<'BANNER'
   ____ _ _   _                _      _   _             _
  / ___(_) |_| |    ___  __ _| | __ | | | |_   _ _ __ | |_ ___ _ __
 | |  _| | __| |   / _ \/ _` | |/ / | |_| | | | | '_ \| __/ _ \ '__|
 | |_| | | |_| |__|  __/ (_| |   <  |  _  | |_| | | | | ||  __/ |
  \____|_|\__|_____\___|\__,_|_|\_\ |_| |_|\__,_|_| |_|\__\___|_|   BR
BANNER
  printf '%s' "$C_RESET"
  printf '%s  v%s — recon de .git exposto + varredura de secrets no histórico%s\n\n' \
    "$C_DIM" "$VERSION" "$C_RESET"

  printf '%s' "$C_YELLOW"
  cat <<'LEGAL'
  ┌────────────────────────────────────────────────────────────────────┐
  │  AVISO LEGAL — LEIA ANTES DE USAR                                     │
  │  Use SOMENTE contra sistemas que você tem AUTORIZAÇÃO por escrito     │
  │  para testar. Acesso não autorizado a dispositivo informático é       │
  │  crime no Brasil (Lei 12.737/2012 - Lei Carolina Dieckmann). O        │
  │  tratamento de dados obtidos está sujeito à LGPD (Lei 13.709/2018).   │
  │  O autor e o canal NÃO se responsabilizam por uso indevido.           │
  └────────────────────────────────────────────────────────────────────┘
LEGAL
  printf '%s\n' "$C_RESET"
}

# ==============================================================================
# Ajuda
# ==============================================================================
usage() {
  cat <<EOF
${C_BOLD}Uso:${C_RESET}
  ./gitleak_hunter_br.sh -t alvo.com.br
  ./gitleak_hunter_br.sh -f lista_alvos.txt --output json --delay 2
  ./gitleak_hunter_br.sh --demo

${C_BOLD}Flags:${C_RESET}
  -t <alvo>            Alvo único (domínio ou URL). Ex: exemplo.com.br
  -f <arquivo>         Lista de alvos, um por linha
  --output <fmt>       Formato do relatório: markdown (padrão) ou json
  --delay <segundos>   Pausa entre requests (rate limiting). Padrão: ${DELAY}
  --demo               Cria um repositório .git sintético local com secrets
                       fake e roda a análise completa — sem internet, sem alvo
  --no-confirm         Pula o gate de autorização (SÓ para pipeline já autorizado)
  -h, --help           Mostra esta ajuda

${C_BOLD}Saída:${C_RESET}
  Relatórios salvos em ${REPORTS_DIR}/<alvo>_<timestamp>.{md,json}
  Segredos são MASCARADOS no terminal. O relatório em arquivo contém o
  segredo completo (necessário para o PoC) — trate o arquivo como sensível.
EOF
}

# ==============================================================================
# Sanitização de entrada — evita injeção de comando via nome de alvo malicioso
# Retorna: host[:porta] limpo em stdout; código != 0 se inválido
# ==============================================================================
sanitize_target() {
  local raw="$1" host
  # remove scheme e qualquer path/query
  host="${raw#http://}"; host="${host#https://}"
  host="${host%%/*}"; host="${host%%\?*}"
  host="${host// /}"   # sem espaços
  # whitelist estrita: letras, dígitos, ponto, underscore, dois-pontos (porta) e hífen
  if [[ -z "$host" || ! "$host" =~ ^[A-Za-z0-9._:-]+$ ]]; then
    log_err "Alvo inválido/rejeitado pela sanitização: '$raw'"
    return 1
  fi
  printf '%s' "$host"
}

# Detecta o scheme original informado (default https)
scheme_of() {
  local raw="$1"
  case "$raw" in
    http://*)  printf 'http'  ;;
    https://*) printf 'https' ;;
    *)         printf 'https' ;;
  esac
}

# ==============================================================================
# Gate de confirmação de autorização
# ==============================================================================
confirm_authorization() {
  local alvo="$1"
  if [[ "$NO_CONFIRM" -eq 1 ]]; then
    log_warn "Gate de autorização pulado (--no-confirm) para: $alvo"
    return 0
  fi
  printf '%s' "$C_YELLOW$C_BOLD"
  printf '\n  Você declara ter AUTORIZAÇÃO explícita para testar "%s"?\n' "$alvo"
  printf '%s' "$C_RESET"
  local resp
  read -r -p "  Prosseguir com a varredura ativa? [s/N] " resp
  case "$resp" in
    s|S|sim|SIM|y|Y|yes) log_ok "Autorização confirmada para $alvo"; return 0 ;;
    *) log_warn "Varredura cancelada para $alvo (sem confirmação)."; return 1 ;;
  esac
}

# ==============================================================================
# HTTP GET com curl — respeita --delay, timeout e UA.
# uso: http_get <url> [arquivo_destino]
#   sem destino -> corpo em stdout
# Retorna 0 se HTTP 2xx.
# ==============================================================================
http_get() {
  local url="$1" dest="${2:-}" code
  if [[ -n "$dest" ]]; then
    code="$(curl -s -k -L --path-as-is --max-time "$TIMEOUT" \
            -A "$UA" -o "$dest" -w '%{http_code}' "$url" 2>/dev/null)"
    # nunca deixa corpo de erro (ex: página 404 HTML) gravado no arquivo —
    # isso corromperia arquivos de controle do git (packed-refs, refs, etc.)
    [[ "$code" =~ ^2 ]] || rm -f "$dest"
  else
    # separa corpo e status
    local tmp; tmp="$(mktemp)"
    code="$(curl -s -k -L --path-as-is --max-time "$TIMEOUT" \
            -A "$UA" -o "$tmp" -w '%{http_code}' "$url" 2>/dev/null)"
    cat "$tmp"; rm -f "$tmp"
  fi
  [[ "$DELAY" != "0" ]] && sleep "$DELAY"
  [[ "$code" =~ ^2 ]]
}

# ==============================================================================
# MÓDULO 1 — Detecção
# Confirma .git exposto pelo CONTEÚDO, não só pelo HTTP 200.
# Retorna 0 se confirmado. Publica $BASE_URL global.
# ==============================================================================
detect_git() {
  local host="$1" scheme="$2"
  local base="${scheme}://${host}/.git"
  local head_body confirmations=0

  log_info "Módulo 1 — Detecção em ${scheme}://${host}/.git/"

  # 1) /.git/HEAD — precisa começar com 'ref: refs/' ou ser um SHA de 40 hex
  head_body="$(http_get "${base}/HEAD")"
  if [[ "$head_body" =~ ^ref:\ refs/ ]] || [[ "$head_body" =~ ^[0-9a-f]{40}$ ]]; then
    log_ok "/.git/HEAD válido: $(printf '%s' "$head_body" | head -1)"
    confirmations=$((confirmations+1))
  else
    log_warn "/.git/HEAD ausente ou inválido (possível 404 custom / não exposto)."
    return 1
  fi

  # 2) /.git/config — deve conter seção [core]
  if http_get "${base}/config" | grep -qi '\[core\]'; then
    log_ok "/.git/config confirmado ([core] presente)"
    confirmations=$((confirmations+1))
  fi

  # 3) /.git/index — arquivo binário começa com a assinatura 'DIRC'
  local idx_tmp; idx_tmp="$(mktemp)"
  if http_get "${base}/index" "$idx_tmp" && [[ "$(head -c 4 "$idx_tmp" 2>/dev/null)" == "DIRC" ]]; then
    log_ok "/.git/index confirmado (assinatura DIRC)"
    confirmations=$((confirmations+1))
  fi
  rm -f "$idx_tmp"

  # 4) /.git/logs/HEAD — reflog, contém SHAs hex (surface de commits "apagados")
  if http_get "${base}/logs/HEAD" | grep -qE '[0-9a-f]{40}'; then
    log_ok "/.git/logs/HEAD confirmado (reflog com histórico apagado disponível!)"
    confirmations=$((confirmations+1))
  fi

  if [[ "$confirmations" -ge 1 ]]; then
    log_ok "Confirmação cruzada: ${confirmations}/4 indicadores. .git EXPOSTO."
    BASE_URL="$base"
    return 0
  fi
  log_err "Nenhuma confirmação de conteúdo. Provável falso positivo — pulando."
  return 1
}

# ==============================================================================
# MÓDULO 2 — Reconstrução do repositório
# Baixa objects/refs/index e monta um .git funcional local usando o Git da
# máquina de quem roda (o alvo NÃO precisa de git). Publica $WORKDIR global.
# ==============================================================================
declare -A SEEN_OBJ
QUEUE=()

# baixa um object solto e, se for válido, enfileira para parsing recursivo
fetch_object() {
  local sha="$1"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ -n "${SEEN_OBJ[$sha]:-}" ]] && return 0
  SEEN_OBJ[$sha]=1
  local d="${sha:0:2}" f="${sha:2}"
  local dest="${GIT_DIR}/objects/${d}/${f}"
  if [[ -f "$dest" ]]; then QUEUE+=("$sha"); return 0; fi
  mkdir -p "${GIT_DIR}/objects/${d}"
  if http_get "${BASE_URL}/objects/${d}/${f}" "$dest"; then
    if git -C "$WORKDIR" cat-file -t "$sha" >/dev/null 2>&1; then
      QUEUE+=("$sha")
      return 0
    fi
  fi
  rm -f "$dest"
  return 1
}

# extrai SHAs referenciados por um object e os baixa
walk_object() {
  local sha="$1" type
  type="$(git -C "$WORKDIR" cat-file -t "$sha" 2>/dev/null)" || return
  case "$type" in
    commit)
      git -C "$WORKDIR" cat-file -p "$sha" 2>/dev/null \
        | awk '/^tree /{print $2} /^parent /{print $2}' \
        | while read -r ref; do echo "$ref"; done
      ;;
    tree)
      git -C "$WORKDIR" cat-file -p "$sha" 2>/dev/null | awk '{print $3}'
      ;;
    tag)
      git -C "$WORKDIR" cat-file -p "$sha" 2>/dev/null | awk '/^object /{print $2}'
      ;;
  esac
}

reconstruct_repo() {
  local host="$1"
  WORKDIR="$(mktemp -d)"
  GIT_DIR="${WORKDIR}/.git"
  log_info "Módulo 2 — Reconstruindo repositório em: $WORKDIR"

  if ! command -v git >/dev/null 2>&1; then
    log_err "Git não instalado — módulo de reconstrução indisponível. (degradação)"
    return 1
  fi

  git init -q "$WORKDIR" || { log_err "Falha no git init local"; return 1; }
  mkdir -p "${GIT_DIR}/objects/pack" "${GIT_DIR}/refs/heads" "${GIT_DIR}/logs"

  # --- arquivos de metadados conhecidos ---
  local meta
  for meta in HEAD config index packed-refs ORIG_HEAD description \
              info/refs info/exclude objects/info/packs \
              logs/HEAD FETCH_HEAD COMMIT_EDITMSG; do
    mkdir -p "${GIT_DIR}/$(dirname "$meta")"
    http_get "${BASE_URL}/${meta}" "${GIT_DIR}/${meta}" 2>/dev/null || true
    [[ -s "${GIT_DIR}/${meta}" ]] && log_ok "baixado: .git/${meta}"
  done

  # --- refs comuns + o que HEAD aponta ---
  local roots=() ref sha
  local common_refs=(refs/heads/master refs/heads/main refs/heads/develop \
                     refs/heads/dev refs/heads/staging refs/heads/production \
                     refs/remotes/origin/master refs/remotes/origin/main)
  if [[ -f "${GIT_DIR}/HEAD" ]]; then
    ref="$(sed -n 's/^ref: //p' "${GIT_DIR}/HEAD" | head -1)"
    [[ -n "$ref" ]] && common_refs+=("$ref")
  fi
  for ref in "${common_refs[@]}"; do
    mkdir -p "${GIT_DIR}/$(dirname "$ref")"
    if http_get "${BASE_URL}/${ref}" "${GIT_DIR}/${ref}" 2>/dev/null; then
      sha="$(grep -oE '[0-9a-f]{40}' "${GIT_DIR}/${ref}" 2>/dev/null | head -1)"
      [[ -n "$sha" ]] && { roots+=("$sha"); log_ok "ref ${ref} -> ${sha:0:8}"; }
    fi
  done

  # --- SHAs de packed-refs e de todos os logs (inclui commits "apagados") ---
  local logf
  for logf in "${GIT_DIR}/packed-refs" "${GIT_DIR}/info/refs" "${GIT_DIR}/logs/HEAD"; do
    [[ -f "$logf" ]] || continue
    while read -r sha; do roots+=("$sha"); done \
      < <(grep -oE '[0-9a-f]{40}' "$logf" 2>/dev/null | sort -u)
  done
  # tenta logs por-branch dos refs conhecidos
  for ref in "${common_refs[@]}"; do
    if http_get "${BASE_URL}/logs/${ref}" "${GIT_DIR}/logs/${ref}" 2>/dev/null; then
      while read -r sha; do roots+=("$sha"); done \
        < <(grep -oE '[0-9a-f]{40}' "${GIT_DIR}/logs/${ref}" 2>/dev/null)
    fi
  done

  # --- packfiles listados em objects/info/packs ---
  local packname
  if [[ -f "${GIT_DIR}/objects/info/packs" ]]; then
    while read -r _ packname; do
      [[ "$packname" == pack-*.pack ]] || continue
      http_get "${BASE_URL}/objects/pack/${packname}" \
               "${GIT_DIR}/objects/pack/${packname}" 2>/dev/null || true
      http_get "${BASE_URL}/objects/pack/${packname%.pack}.idx" \
               "${GIT_DIR}/objects/pack/${packname%.pack}.idx" 2>/dev/null || true
      log_ok "packfile: ${packname}"
    done < "${GIT_DIR}/objects/info/packs"
    # enumera SHAs contidos nos packs para seguir referências soltas
    local idx
    for idx in "${GIT_DIR}"/objects/pack/*.idx; do
      [[ -f "$idx" ]] || continue
      while read -r sha; do roots+=("$sha"); done \
        < <(git -C "$WORKDIR" verify-pack -v "$idx" 2>/dev/null \
            | grep -oE '^[0-9a-f]{40}')
    done
  fi

  # --- SHAs de blobs referenciados pelo index (estado atual) ---
  if [[ -f "${GIT_DIR}/index" ]]; then
    while read -r _ sha _; do roots+=("$sha"); done \
      < <(git -C "$WORKDIR" ls-files -s 2>/dev/null)
  fi

  if [[ "${#roots[@]}" -eq 0 ]]; then
    log_err "Nenhum SHA raiz encontrado — impossível reconstruir."
    return 1
  fi

  # --- BFS: baixa objects soltos seguindo commit -> tree -> parent -> blobs ---
  log_info "Baixando objects (BFS a partir de ${#roots[@]} raízes)..."
  for sha in "${roots[@]}"; do fetch_object "$sha"; done
  local i=0 cur child
  while [[ "$i" -lt "${#QUEUE[@]}" ]]; do
    cur="${QUEUE[$i]}"; i=$((i+1))
    while read -r child; do
      [[ -n "$child" ]] && fetch_object "$child"
    done < <(walk_object "$cur")
  done
  log_ok "Objects obtidos: ${#SEEN_OBJ[@]}"

  # --- recria refs para TODA commit tip (inclui dangling), p/ git log --all ---
  git -C "$WORKDIR" index-pack "${GIT_DIR}"/objects/pack/*.pack >/dev/null 2>&1 || true
  local -A is_parent all_commits
  while read -r sha; do
    all_commits["$sha"]=1
    while read -r p; do is_parent["$p"]=1; done \
      < <(git -C "$WORKDIR" cat-file -p "$sha" 2>/dev/null | awk '/^parent /{print $2}')
  done < <(git -C "$WORKDIR" cat-file --batch-all-objects \
             --batch-check='%(objecttype) %(objectname)' 2>/dev/null \
           | awk '$1=="commit"{print $2}')

  local n_tips=0
  for sha in "${!all_commits[@]}"; do
    if [[ -z "${is_parent[$sha]:-}" ]]; then
      git -C "$WORKDIR" update-ref "refs/recovered/tip-${sha:0:8}" "$sha" 2>/dev/null \
        && n_tips=$((n_tips+1))
    fi
  done
  log_ok "Commits recuperados: ${#all_commits[@]} (tips/branches: ${n_tips})"

  # garante um HEAD utilizável
  git -C "$WORKDIR" rev-parse --verify HEAD >/dev/null 2>&1 || {
    for sha in "${!all_commits[@]}"; do
      git -C "$WORKDIR" update-ref HEAD "$sha" 2>/dev/null && break
    done
  }
  return 0
}

# ==============================================================================
# Mascaramento de secret para o terminal (primeiros 4 + asteriscos + últimos 4)
# ==============================================================================
mask_secret() {
  local s="$1" n="${#1}"
  if [[ "$n" -le 8 ]]; then
    printf '********'
  else
    local mid=$((n-8)) stars
    stars="$(printf '%*s' "$mid" '' | tr ' ' '*')"
    printf '%s%s%s' "${s:0:4}" "$stars" "${s: -4}"
  fi
}

# escape mínimo para JSON
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/}"
  printf '%s' "$s"
}

# arquivo TSV temporário acumulando achados
FINDINGS_TSV=""

# registra um achado (campos separados por TAB)
# sev  tipo  arquivo  commit  data  autor  masked  full  status  reproduzir
add_finding() {
  local sev="$1" tipo="$2" file="$3" commit="$4" cdate="$5" \
        author="$6" full="$7" status="$8" repro="$9"
  local masked; masked="$(mask_secret "$full")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sev" "$tipo" "$file" "$commit" "$cdate" "$author" \
    "$masked" "$full" "$status" "$repro" >> "$FINDINGS_TSV"
  case "$sev" in
    CRITICO) COUNT_CRIT=$((COUNT_CRIT+1)); log_crit "$tipo em $file @ ${commit:0:7} -> $masked" ;;
    ALTO)    COUNT_HIGH=$((COUNT_HIGH+1)); printf '%s[ALTO]%s %s em %s @ %s -> %s\n' "$C_MAGENTA" "$C_RESET" "$tipo" "$file" "${commit:0:7}" "$masked" ;;
    MEDIO)   COUNT_MED=$((COUNT_MED+1));  printf '%s[MÉDIO]%s %s em %s @ %s -> %s\n' "$C_YELLOW" "$C_RESET" "$tipo" "$file" "${commit:0:7}" "$masked" ;;
  esac
}

# ==============================================================================
# MÓDULO 3 — Varredura de secrets em TODO o histórico
# ==============================================================================
scan_secrets() {
  local wd="$1"
  log_info "Módulo 3 — Varrendo secrets em todo o histórico (git log --all)"

  # conjunto de arquivos deletados em algum ponto (achados mais valiosos)
  local -A deleted_files
  while read -r path; do
    [[ -n "$path" ]] && deleted_files["$path"]=1
  done < <(git -C "$wd" log --all --diff-filter=D --name-only --pretty=format: 2>/dev/null \
           | sed '/^$/d' | sort -u)

  # arquivos presentes no HEAD atual
  local -A head_files
  while read -r path; do
    [[ -n "$path" ]] && head_files["$path"]=1
  done < <(git -C "$wd" ls-tree -r --name-only HEAD 2>/dev/null)

  local commit
  while read -r commit; do
    [[ -z "$commit" ]] && continue
    COMMITS_ANALYZED=$((COMMITS_ANALYZED+1))

    # metadados do commit
    local meta author cdate subject
    meta="$(git -C "$wd" show -s --format='%ae%x1f%ad%x1f%s' --date=short "$commit" 2>/dev/null)"
    author="${meta%%$'\x1f'*}"; meta="${meta#*$'\x1f'}"
    cdate="${meta%%$'\x1f'*}";  subject="${meta#*$'\x1f'}"

    # percorre o diff, rastreando o arquivo atual, testando só linhas adicionadas
    local curfile=""
    while IFS= read -r line; do
      case "$line" in
        '+++ b/'*) curfile="${line#+++ b/}" ;;
        '+++ /dev/null') curfile="" ;;
        '+'*)
          [[ "$line" == '+++'* ]] && continue
          local content="${line:1}"

          # status do arquivo (removido do HEAD = achado de ouro)
          local status="presente no HEAD"
          if [[ -z "${head_files[$curfile]:-}" ]]; then
            if [[ -n "${deleted_files[$curfile]:-}" ]]; then
              status="removido do HEAD (existe só no histórico)"
            else
              status="ausente do HEAD atual"
            fi
          fi

          # .env inteiro commitado
          case "$curfile" in
            .env|*/.env|*.env)
              add_finding "CRITICO" "Arquivo .env commitado" "$curfile" \
                "$commit" "$cdate" "$author" "$content" "$status" \
                "git show ${commit}:${curfile}"
              ;;
          esac

          # aplica cada padrão de secret
          local entry name sev regex token
          for entry in "${SECRET_PATTERNS[@]}"; do
            name="${entry%%|*}"; sev="${entry#*|}"; regex="${sev#*|}"; sev="${sev%%|*}"
            token="$(printf '%s' "$content" | grep -oE "$regex" 2>/dev/null | head -1)"
            if [[ -n "$token" ]]; then
              add_finding "$sev" "$name" "$curfile" "$commit" "$cdate" \
                "$author" "$token" "$status" "git show ${commit}:${curfile}"
            fi
          done
          ;;
      esac
    done < <(git -C "$wd" show --no-color --format='' -m --first-parent "$commit" 2>/dev/null)

  done < <(git -C "$wd" rev-list --all 2>/dev/null)

  log_ok "Commits analisados: ${COMMITS_ANALYZED}"
}

# ==============================================================================
# Nota de exposição 0-10 (estilo CyberGuard Scan)
# ==============================================================================
exposure_score() {
  local raw=$(( COUNT_CRIT*4 + COUNT_HIGH*2 + COUNT_MED ))
  local score=$raw
  [[ "$score" -gt 10 ]] && score=10
  if [[ "$COUNT_CRIT" -gt 0 && "$score" -lt 8 ]]; then score=8; fi
  if [[ "$raw" -eq 0 ]]; then score=0; fi
  printf '%s' "$score"
}

# ==============================================================================
# MÓDULO 4 — Relatório (markdown + json)
# ==============================================================================
generate_report() {
  local alvo="$1" elapsed="$2"
  mkdir -p "$REPORTS_DIR"
  local safe; safe="$(printf '%s' "$alvo" | tr -c 'A-Za-z0-9._-' '_')"
  local base="${REPORTS_DIR}/${safe}_${NOW_TS}"
  local score; score="$(exposure_score)"
  local total=$(( COUNT_CRIT + COUNT_HIGH + COUNT_MED ))

  # ---------- Markdown ----------
  {
    printf '# GitLeak Hunter BR — Relatório\n\n'
    printf -- '- **Alvo:** `%s`\n' "$alvo"
    printf -- '- **Data da análise:** %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf -- '- **Commits analisados:** %s\n' "$COMMITS_ANALYZED"
    printf -- '- **Tempo de execução:** %ss\n' "$elapsed"
    printf -- '- **Nota de exposição:** %s/10\n\n' "$score"
    printf '> ⚠️ Este relatório contém secrets COMPLETOS (não mascarados) para fins de PoC. Trate como confidencial.\n\n'
    printf '## Resumo executivo\n\n'
    printf '| Severidade | Qtd |\n|---|---|\n'
    printf '| 🔴 Crítico | %s |\n' "$COUNT_CRIT"
    printf '| 🟠 Alto | %s |\n' "$COUNT_HIGH"
    printf '| 🟡 Médio | %s |\n' "$COUNT_MED"
    printf '| **Total** | **%s** |\n\n' "$total"
    printf '## Achados\n\n'

    if [[ ! -s "$FINDINGS_TSV" ]]; then
      printf '_Nenhum secret encontrado no histórico._\n'
    else
      local sev tipo file commit cdate author masked full status repro emoji
      # ordena por severidade (CRITICO, ALTO, MEDIO)
      local s
      for s in CRITICO ALTO MEDIO; do
        while IFS=$'\t' read -r sev tipo file commit cdate author masked full status repro; do
          [[ "$sev" == "$s" ]] || continue
          case "$sev" in
            CRITICO) emoji='🔴 CRÍTICO' ;;
            ALTO)    emoji='🟠 ALTO' ;;
            MEDIO)   emoji='🟡 MÉDIO' ;;
          esac
          printf '### %s — %s\n\n' "$emoji" "$tipo"
          printf -- '- **Arquivo:** `%s`\n' "$file"
          printf -- '- **Status atual:** %s\n' "$status"
          printf -- '- **Commit:** `%s` — "%s"\n' "${commit:0:7}" \
            "$(git -C "$LAST_WD" show -s --format='%s' "$commit" 2>/dev/null)"
          printf -- '- **Autor:** %s\n' "$author"
          printf -- '- **Data:** %s\n' "$cdate"
          printf -- '- **Secret (mascarado):** `%s`\n' "$masked"
          printf -- '- **Secret (completo):** `%s`\n' "$full"
          printf -- '- **Como reproduzir:** `%s`\n\n' "$repro"
        done < "$FINDINGS_TSV"
      done
    fi
  } > "${base}.md"

  # ---------- JSON ----------
  {
    printf '{\n'
    printf '  "alvo": "%s",\n' "$(json_escape "$alvo")"
    printf '  "data_analise": "%s",\n' "$(date '+%Y-%m-%dT%H:%M:%S')"
    printf '  "commits_analisados": %s,\n' "$COMMITS_ANALYZED"
    printf '  "tempo_execucao_s": %s,\n' "$elapsed"
    printf '  "nota_exposicao": %s,\n' "$score"
    printf '  "resumo": { "critico": %s, "alto": %s, "medio": %s, "total": %s },\n' \
      "$COUNT_CRIT" "$COUNT_HIGH" "$COUNT_MED" "$total"
    printf '  "achados": [\n'
    if [[ -s "$FINDINGS_TSV" ]]; then
      local first=1 sev tipo file commit cdate author masked full status repro
      while IFS=$'\t' read -r sev tipo file commit cdate author masked full status repro; do
        [[ "$first" -eq 0 ]] && printf ',\n'
        first=0
        printf '    {\n'
        printf '      "severidade": "%s",\n' "$(json_escape "$sev")"
        printf '      "tipo": "%s",\n' "$(json_escape "$tipo")"
        printf '      "arquivo": "%s",\n' "$(json_escape "$file")"
        printf '      "commit": "%s",\n' "$(json_escape "$commit")"
        printf '      "data": "%s",\n' "$(json_escape "$cdate")"
        printf '      "autor": "%s",\n' "$(json_escape "$author")"
        printf '      "secret_mascarado": "%s",\n' "$(json_escape "$masked")"
        printf '      "secret_completo": "%s",\n' "$(json_escape "$full")"
        printf '      "status_atual": "%s",\n' "$(json_escape "$status")"
        printf '      "reproduzir": "%s"\n' "$(json_escape "$repro")"
        printf '    }'
      done < "$FINDINGS_TSV"
      printf '\n'
    fi
    printf '  ]\n'
    printf '}\n'
  } > "${base}.json"

  log_ok "Relatório Markdown: ${base}.md"
  log_ok "Relatório JSON:     ${base}.json"

  # resumo no terminal
  printf '\n%s══ Resumo executivo ══%s\n' "$C_BOLD" "$C_RESET"
  printf '  Crítico: %s%s%s | Alto: %s%s%s | Médio: %s%s%s | Total: %s\n' \
    "$C_RED" "$COUNT_CRIT" "$C_RESET" "$C_MAGENTA" "$COUNT_HIGH" "$C_RESET" \
    "$C_YELLOW" "$COUNT_MED" "$C_RESET" "$total"
  printf '  Commits analisados: %s | Tempo: %ss | Nota de exposição: %s%s/10%s\n\n' \
    "$COMMITS_ANALYZED" "$elapsed" "$C_BOLD" "$score" "$C_RESET"

  if [[ "$OUTPUT" == "json" ]]; then LAST_REPORT="${base}.json"; else LAST_REPORT="${base}.md"; fi
}

# ==============================================================================
# Reseta estado por-alvo
# ==============================================================================
reset_state() {
  SEEN_OBJ=(); QUEUE=()
  COUNT_CRIT=0; COUNT_HIGH=0; COUNT_MED=0; COMMITS_ANALYZED=0
  FINDINGS_TSV="$(mktemp)"
}

# ==============================================================================
# Pipeline completo para um alvo (detecção -> reconstrução -> scan -> relatório)
# ==============================================================================
process_target() {
  local raw="$1" host scheme start elapsed
  host="$(sanitize_target "$raw")" || return 1
  scheme="$(scheme_of "$raw")"

  printf '\n%s────────── Alvo: %s ──────────%s\n' "$C_CYAN$C_BOLD" "$host" "$C_RESET"
  confirm_authorization "$host" || return 1

  reset_state
  start="$(date +%s)"

  if ! detect_git "$host" "$scheme"; then
    # fallback: tenta o outro scheme
    local other="http"; [[ "$scheme" == "http" ]] && other="https"
    log_info "Tentando fallback via ${other}://"
    detect_git "$host" "$other" || { log_err "Alvo não vulnerável / .git não exposto."; return 1; }
  fi

  reconstruct_repo "$host" || { log_err "Reconstrução falhou para $host."; return 1; }
  LAST_WD="$WORKDIR"
  scan_secrets "$WORKDIR"

  elapsed=$(( $(date +%s) - start ))
  generate_report "$host" "$elapsed"

  log_info "Repositório reconstruído disponível em: $WORKDIR (git log --all funciona)"
}

# ==============================================================================
# MODO DEMO — cria um .git sintético local com secrets fake e roda a análise
# completa. Sem internet, sem alvo real.
# ==============================================================================
run_demo() {
  log_info "Modo DEMO — criando repositório .git sintético com secrets fake"
  command -v git >/dev/null 2>&1 || die "Git é necessário para o modo demo."

  reset_state
  local start; start="$(date +%s)"
  local d; d="$(mktemp -d)"
  (
    cd "$d" || exit 1
    git init -q
    git config user.email "dev@empresa.com.br"
    git config user.name "Dev Exemplo"
    export GIT_AUTHOR_DATE="2019-03-10T10:00:00" GIT_COMMITTER_DATE="2019-03-10T10:00:00"

    # commit 1 — credenciais AWS hardcoded
    mkdir -p config
    cat > config/aws_credentials.py <<'PY'
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PY
    git add -A; git commit -q -m "add app config"

    # commit 2 — .env inteiro commitado (JWT, DB, API key)
    export GIT_AUTHOR_DATE="2019-03-12T09:00:00" GIT_COMMITTER_DATE="2019-03-12T09:00:00"
    cat > .env <<'ENV'
API_KEY=sk_live_51H8x9zExampleTokenValue1234567890abcd
DATABASE_URL=postgres://admin:SuperSecret123@db.internal:5432/prod
JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcDEF123456_secretsignature
PASSWORD=Prod@Senha!2019
ENV
    git add -A; git commit -q -m "wire up integrations"

    # commit 3 — "remove hardcoded creds" (mas o histórico guarda tudo!)
    export GIT_AUTHOR_DATE="2019-03-14T15:30:00" GIT_COMMITTER_DATE="2019-03-14T15:30:00"
    git rm -q config/aws_credentials.py .env
    echo "config/" > .gitignore
    echo ".env" >> .gitignore
    git add -A; git commit -q -m "remove hardcoded creds"

    # commit 4 — código inocente atual
    export GIT_AUTHOR_DATE="2019-04-01T11:00:00" GIT_COMMITTER_DATE="2019-04-01T11:00:00"
    echo "print('hello world')" > app.py
    git add -A; git commit -q -m "refactor entrypoint"
  ) || die "Falha ao montar o repositório de demo."

  log_ok "Repositório demo criado em: $d"
  LAST_WD="$d"
  scan_secrets "$d"
  local elapsed=$(( $(date +%s) - start ))
  generate_report "demo-local" "$elapsed"

  printf '%sDica:%s inspecione o repo demo com:\n  git -C %s log --all --oneline\n\n' \
    "$C_DIM" "$C_RESET" "$d"
}

# ==============================================================================
# Verificação de dependências
# ==============================================================================
check_deps() {
  local missing=()
  local dep
  for dep in curl grep awk sed; do
    command -v "$dep" >/dev/null 2>&1 || missing+=("$dep")
  done
  if [[ "${#missing[@]}" -gt 0 ]]; then
    die "Dependências ausentes: ${missing[*]}"
  fi
  if ! command -v git >/dev/null 2>&1; then
    log_warn "Git não encontrado — reconstrução e demo ficarão indisponíveis (degradação)."
  fi
}

# ==============================================================================
# Parse de argumentos
# ==============================================================================
parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      -t)          TARGET="$2"; shift 2 ;;
      -f)          TARGET_FILE="$2"; shift 2 ;;
      --output)    OUTPUT="$2"; shift 2 ;;
      --delay)     DELAY="$2"; shift 2 ;;
      --demo)      DEMO=1; shift ;;
      --no-confirm) NO_CONFIRM=1; shift ;;
      -h|--help)   print_banner; usage; exit 0 ;;
      *)           log_err "Flag desconhecida: $1"; usage; exit 1 ;;
    esac
  done

  case "$OUTPUT" in
    json|markdown) : ;;
    *) die "Formato inválido: '$OUTPUT' (use json ou markdown)" ;;
  esac
  if [[ ! "$DELAY" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    die "--delay deve ser numérico (segundos)."
  fi
}

# ==============================================================================
# main
# ==============================================================================
main() {
  parse_args "$@"
  print_banner
  check_deps

  if [[ "$DEMO" -eq 1 ]]; then
    run_demo
    exit 0
  fi

  if [[ -z "$TARGET" && -z "$TARGET_FILE" ]]; then
    usage
    die "Informe um alvo (-t), uma lista (-f) ou use --demo."
  fi

  if [[ -n "$TARGET" ]]; then
    process_target "$TARGET" || true
  fi

  if [[ -n "$TARGET_FILE" ]]; then
    [[ -f "$TARGET_FILE" ]] || die "Arquivo de alvos não encontrado: $TARGET_FILE"
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="$(printf '%s' "$line" | sed 's/#.*//' | tr -d '[:space:]')"
      [[ -z "$line" ]] && continue
      process_target "$line" || true
    done < "$TARGET_FILE"
  fi

  log_ok "Concluído."
}

main "$@"
