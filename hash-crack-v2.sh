#!/usr/bin/env bash
# ============================================================
#  hashcrack.sh  —  Hash Auto-Identifier & Cracker
#  İstifadə:
#    ./hashcrack.sh <hash> [wordlist]           # saltsız
#    ./hashcrack.sh <hash> [wordlist] -s <salt> # saltlı
# ============================================================

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'

HASH="$1"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"
HASH_FILE="/tmp/_hc_target.txt"
RESULT_FILE="/tmp/_hc_result.txt"
FOUND=""
SALT=""

# -s <salt> arqumentini parse et
for i in "$@"; do
  if [[ "$PREV" == "-s" ]]; then SALT="$i"; fi
  PREV="$i"
done

# ── Format tələb edən mode-lar (saltlı rejimdə bunlar da sınanır) ──
declare -A SKIP_MODES
SKIP_MODES[1100]=1; SKIP_MODES[2100]=1; SKIP_MODES[7300]=1
SKIP_MODES[8300]=1; SKIP_MODES[5500]=1; SKIP_MODES[5600]=1

# ── Saltlı mode cədvəli: hash uzunluğuna görə ─────────────
# Formatlar: pass.salt və salt.pass hər ikisi sınanır
declare -A SALTED_MODES_32   # MD5 (32 hex)
SALTED_MODES_32["md5(pass.salt)"]="10"
SALTED_MODES_32["md5(salt.pass)"]="20"
SALTED_MODES_32["md5(pass.salt) — unicode"]="30"
SALTED_MODES_32["md5(salt.pass) — unicode"]="40"
SALTED_MODES_32["HMAC-MD5(pass)"]="50"
SALTED_MODES_32["HMAC-MD5(key=salt)"]="60"

declare -A SALTED_MODES_40   # SHA1 (40 hex)
SALTED_MODES_40["sha1(pass.salt)"]="110"
SALTED_MODES_40["sha1(salt.pass)"]="120"
SALTED_MODES_40["sha1(pass.salt) — unicode"]="130"
SALTED_MODES_40["sha1(salt.pass) — unicode"]="140"
SALTED_MODES_40["HMAC-SHA1(pass)"]="150"
SALTED_MODES_40["HMAC-SHA1(key=salt)"]="160"

declare -A SALTED_MODES_64   # SHA256 (64 hex)
SALTED_MODES_64["sha256(pass.salt)"]="1410"
SALTED_MODES_64["sha256(salt.pass)"]="1420"
SALTED_MODES_64["sha256(pass.salt) — unicode"]="1430"
SALTED_MODES_64["sha256(salt.pass) — unicode"]="1440"
SALTED_MODES_64["HMAC-SHA256(pass)"]="1450"
SALTED_MODES_64["HMAC-SHA256(key=salt)"]="1460"

declare -A SALTED_MODES_128  # SHA512 (128 hex)
SALTED_MODES_128["sha512(pass.salt)"]="1710"
SALTED_MODES_128["sha512(salt.pass)"]="1720"
SALTED_MODES_128["sha512(pass.salt) — unicode"]="1730"
SALTED_MODES_128["sha512(salt.pass) — unicode"]="1740"
SALTED_MODES_128["HMAC-SHA512(pass)"]="1750"
SALTED_MODES_128["HMAC-SHA512(key=salt)"]="1760"

# ── Yardımçı ──────────────────────────────────────────────
banner() {
  echo -e "${CYAN}${BOLD}"
  echo    "╔══════════════════════════════════════════╗"
  echo    "║     Hash Auto-Identifier & Cracker       ║"
  echo -e "╚══════════════════════════════════════════╝${NC}"
}
die()  { echo -e "${RED}[!] $1${NC}"; exit 1; }
info() { echo -e "${CYAN}[*] $1${NC}"; }
ok()   { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[-] $1${NC}"; }

check_deps() {
  command -v hashcat &>/dev/null || warn "hashcat tapılmadı  →  sudo apt install hashcat"
  command -v john    &>/dev/null || warn "john tapılmadı     →  sudo apt install john"
  command -v hashid  &>/dev/null || warn "hashid tapılmadı   →  pip3 install hashid"
  command -v hashcat &>/dev/null || command -v john &>/dev/null || \
    die "Nə hashcat, nə john var. Ən az biri lazımdır."
}

# ── hashid çıxışını parse et ──────────────────────────────
parse_hashid_modes() {
  declare -gA TYPE_MAP
  while IFS= read -r line; do
    if [[ "$line" =~ \[Hashcat\ Mode:\ ([0-9]+)\] ]]; then
      local mode="${BASH_REMATCH[1]}"
      [[ -n "${SKIP_MODES[$mode]}" ]] && continue
      local name
      name=$(echo "$line" | sed 's/\[+\] //' | sed 's/ \[Hashcat Mode:.*$//')
      TYPE_MAP["$name"]="$mode"
    fi
  done < <(hashid -m "$HASH" 2>/dev/null)
}

# ── Manual aşkarlama ─────────────────────────────────────
detect_manual() {
  declare -gA TYPE_MAP
  local h="$HASH" len=${#HASH}
  case $len in
    32) [[ "$h" =~ ^[a-fA-F0-9]+$ ]] && TYPE_MAP["MD5"]="0" TYPE_MAP["NTLM"]="1000" TYPE_MAP["MD4"]="900" ;;
    40) [[ "$h" =~ ^[a-fA-F0-9]+$ ]] && TYPE_MAP["SHA1"]="100" ;;
    64) [[ "$h" =~ ^[a-fA-F0-9]+$ ]] && TYPE_MAP["SHA256"]="1400" ;;
   128) [[ "$h" =~ ^[a-fA-F0-9]+$ ]] && TYPE_MAP["SHA512"]="1700" ;;
  esac
  [[ "$h" =~ ^\$2[ayb]\$ ]] && TYPE_MAP["bcrypt"]="3200"
  [[ "$h" =~ ^\$1\$       ]] && TYPE_MAP["md5crypt"]="500"
  [[ "$h" =~ ^\$6\$       ]] && TYPE_MAP["sha512crypt"]="1800"
  [[ "$h" =~ ^\$5\$       ]] && TYPE_MAP["sha256crypt"]="7400"
  [[ "$h" =~ ^\$P\$       ]] && TYPE_MAP["phpass"]="400"
}

# ── Hash uzunluğuna görə saltlı mode cədvəlini seç ────────
get_salted_map() {
  local len=${#HASH}
  case $len in
    32) declare -gn SALTED_MAP=SALTED_MODES_32  ;;
    40) declare -gn SALTED_MAP=SALTED_MODES_40  ;;
    64) declare -gn SALTED_MAP=SALTED_MODES_64  ;;
   128) declare -gn SALTED_MAP=SALTED_MODES_128 ;;
     *) return 1 ;;
  esac
}

# ── Hashcat ilə bir mode sına ─────────────────────────────
crack_with_hashcat() {
  local mode="$1" name="$2" target_file="$3"
  info "Hashcat: ${BOLD}$name${NC} [mode $mode]"

  rm -f "$RESULT_FILE"

  local hc_stderr
  hc_stderr=$(hashcat -m "$mode" "$target_file" "$WORDLIST" \
    --outfile "$RESULT_FILE" --outfile-format 2 \
    --potfile-disable --quiet --force -O 2>&1)

  if echo "$hc_stderr" | grep -qiE "Separator|Token length|Invalid|No hashes loaded"; then
    warn "  ↳ Format uyğun deyil, keçildi"
    return 1
  fi

  if [[ -s "$RESULT_FILE" ]]; then
    FOUND=$(cat "$RESULT_FILE")
    ok "TAPILDI! [$name]  ${BOLD}$HASH${NC}  →  ${GREEN}${BOLD}$FOUND${NC}"
    return 0
  fi

  local pot_line
  pot_line=$(hashcat -m "$mode" "$target_file" --show --quiet 2>/dev/null \
    | grep -v "Separator\|Token\|Invalid\|No hashes" | grep ":" | tail -n1)

  if [[ -n "$pot_line" ]]; then
    local plain="${pot_line#*:}"
    if [[ -n "$plain" && ! "$plain" =~ (Separator|Token|Invalid) ]]; then
      FOUND="$plain"
      ok "POTFİLDƏ TAPILDI! [$name]  →  ${GREEN}${BOLD}$plain${NC}"
      return 0
    fi
  fi

  warn "  ↳ tapılmadı"
  return 1
}

# ── Saltlı hash-ləri crack et ─────────────────────────────
crack_salted() {
  local salt_file="/tmp/_hc_salted.txt"
  echo "${HASH}:${SALT}" > "$salt_file"

  echo ""
  info "Salt aşkarlandı: ${BOLD}$SALT${NC}"
  info "Hash uzunluğu: ${#HASH} simvol"

  if ! get_salted_map; then
    warn "Bu uzunluq üçün saltlı mode cədvəli yoxdur (${#HASH} simvol)"
    rm -f "$salt_file"
    return
  fi

  local count=${#SALTED_MAP[@]}
  info "Sınanacaq saltlı format sayı: $count"
  echo "──────────────────────────────────────────"

  for name in "${!SALTED_MAP[@]}"; do
    [[ -n "$FOUND" ]] && break
    crack_with_hashcat "${SALTED_MAP[$name]}" "$name" "$salt_file"
  done

  rm -f "$salt_file"
}

# ── Saltsız crack (normal axın) ───────────────────────────
crack_normal() {
  if command -v hashid &>/dev/null; then
    info "hashid ilə aşkarlama..."
    echo ""
    hashid -m "$HASH" 2>/dev/null
    echo ""
    parse_hashid_modes
  fi

  [[ ${#TYPE_MAP[@]} -eq 0 ]] && detect_manual

  echo "──────────────────────────────────────────"

  if command -v hashcat &>/dev/null && [[ ${#TYPE_MAP[@]} -gt 0 ]]; then
    info "Hashcat ilə ${#TYPE_MAP[@]} növ sınanacaq..."
    echo ""
    for name in "${!TYPE_MAP[@]}"; do
      [[ -n "$FOUND" ]] && break
      crack_with_hashcat "${TYPE_MAP[$name]}" "$name" "$HASH_FILE"
    done
  fi

  if [[ -z "$FOUND" ]] && command -v john &>/dev/null; then
    echo ""
    info "John the Ripper ilə sınayır (--format=auto)..."
    john "$HASH_FILE" --wordlist="$WORDLIST" --format=auto 2>/dev/null
    local result
    result=$(john --show "$HASH_FILE" 2>/dev/null | head -n1)
    if [[ "$result" == *":"* ]]; then
      local plain="${result#*:}"; plain="${plain%%:*}"
      if [[ -n "$plain" ]]; then
        FOUND="$plain"
        ok "John ilə TAPILDI!  →  ${GREEN}${BOLD}$plain${NC}"
      fi
    fi
    [[ -z "$FOUND" ]] && warn "John da tapa bilmədi"
  fi
}

# ══════════════════════════════════════════════════════════
#  ANA AXIN
# ══════════════════════════════════════════════════════════
banner

[[ -z "$HASH" ]] && {
  echo -e "${BOLD}İstifadə:${NC}"
  echo "  $0 <hash> [wordlist]"
  echo "  $0 <hash> [wordlist] -s <salt>"
  echo ""
  exit 1
}

[[ -f "$WORDLIST" ]] || die "Wordlist tapılmadı: $WORDLIST"

echo -e "${BOLD}Hədəf hash :${NC} $HASH"
echo -e "${BOLD}Wordlist   :${NC} $WORDLIST"
[[ -n "$SALT" ]] && echo -e "${BOLD}Salt       :${NC} ${YELLOW}$SALT${NC}"
echo "──────────────────────────────────────────"

check_deps

echo "$HASH" > "$HASH_FILE"

if [[ -n "$SALT" ]]; then
  crack_salted
else
  crack_normal
fi

# ── Final nəticə ──────────────────────────────────────────
echo ""
echo    "══════════════════════════════════════════"
if [[ -n "$FOUND" ]]; then
  echo -e "${GREEN}${BOLD}  ✓ NƏTİCƏ: $HASH  →  $FOUND${NC}"
  [[ -n "$SALT" ]] && echo -e "${GREEN}  Salt: $SALT${NC}"
else
  echo -e "${RED}${BOLD}  ✗ Hash crack edilə bilmədi${NC}"
  echo -e "${YELLOW}  İpuçları:"
  echo "  • Daha böyük wordlist istifadə et"
  if [[ -n "$SALT" ]]; then
    echo "  • Salt formatını yoxla: bəzən hex-encoded olur"
    echo "  • Manual: hashcat -m 110 '$HASH:$SALT' rockyou.txt"
  fi
  echo -e "  • Rule attack: hashcat -m <mode> hash.txt rockyou.txt -r best64.rule${NC}"
fi
echo "══════════════════════════════════════════"

rm -f "$HASH_FILE" "$RESULT_FILE"
