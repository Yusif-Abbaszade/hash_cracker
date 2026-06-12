#!/usr/bin/env bash
# ============================================================
#  hashcrack.sh  —  Hash Auto-Identifier & Cracker
#  İstifadə: ./hashcrack.sh <hash> [wordlist]
# ============================================================

# Rənglər — $'...' sintaksisi ilə həm echo həm printf-də işləyir
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'

HASH="$1"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"
HASH_FILE="/tmp/_hc_target.txt"
RESULT_FILE="/tmp/_hc_result.txt"
FOUND=""

# ── Formatı tələb edən mode-lar (user:hash, domain:hash vs) ──
# Bu mode-lar sadə hash ilə işləmir — avtomatik keçilir
declare -A SKIP_MODES
SKIP_MODES[1100]=1   # DCC  (domain\user:hash)
SKIP_MODES[2100]=1   # DCC2 (domain\user:$DCC2...)
SKIP_MODES[7300]=1   # IPMI2 RAKP HMAC-SHA1
SKIP_MODES[8300]=1   # DNSSEC NSEC3
SKIP_MODES[5500]=1   # NetNTLMv1
SKIP_MODES[5600]=1   # NetNTLMv2

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

# ── hashid çıxışını parse edib TYPE_MAP doldurur ──────────
parse_hashid_modes() {
  declare -gA TYPE_MAP
  while IFS= read -r line; do
    if [[ "$line" =~ \[Hashcat\ Mode:\ ([0-9]+)\] ]]; then
      local mode="${BASH_REMATCH[1]}"
      # Format tələb edən mode-ları keç
      if [[ -n "${SKIP_MODES[$mode]}" ]]; then
        local skipped_name
        skipped_name=$(echo "$line" | sed 's/\[+\] //' | sed 's/ \[Hashcat Mode:.*$//')
        warn "Keçildi (xüsusi format tələb edir): $skipped_name [mode $mode]"
        continue
      fi
      local name
      name=$(echo "$line" | sed 's/\[+\] //' | sed 's/ \[Hashcat Mode:.*$//')
      TYPE_MAP["$name"]="$mode"
    fi
  done < <(hashid -m "$HASH" 2>/dev/null)
}

# ── Manual aşkarlama (hashid yoxdursa) ───────────────────
detect_manual() {
  declare -gA TYPE_MAP
  local h="$HASH" len=${#HASH}
  case $len in
    32) [[ "$h" =~ ^[a-fA-F0-9]+$ ]] && TYPE_MAP["MD5"]="0" TYPE_MAP["NTLM"]="1000" TYPE_MAP["MD4"]="900" ;;
    40) [[ "$h" =~ ^[a-fA-F0-9]+$ ]] && TYPE_MAP["SHA1"]="100" ;;
    64) [[ "$h" =~ ^[a-fA-F0-9]+$ ]] && TYPE_MAP["SHA256"]="1400" TYPE_MAP["SHA3-256"]="17300" ;;
    96) [[ "$h" =~ ^[a-fA-F0-9]+$ ]] && TYPE_MAP["SHA384"]="10800" ;;
   128) [[ "$h" =~ ^[a-fA-F0-9]+$ ]] && TYPE_MAP["SHA512"]="1700" TYPE_MAP["SHA3-512"]="17600" ;;
  esac
  [[ "$h" =~ ^\$2[ayb]\$ ]] && TYPE_MAP["bcrypt"]="3200"
  [[ "$h" =~ ^\$1\$      ]] && TYPE_MAP["md5crypt"]="500"
  [[ "$h" =~ ^\$6\$      ]] && TYPE_MAP["sha512crypt"]="1800"
  [[ "$h" =~ ^\$5\$      ]] && TYPE_MAP["sha256crypt"]="7400"
  [[ "$h" =~ ^\$P\$      ]] && TYPE_MAP["phpass"]="400"
  [[ ${#TYPE_MAP[@]} -eq 0 ]] && warn "Manual aşkarlama da növü müəyyən edə bilmədi"
}

# ── Hashcat ilə bir mode sına ─────────────────────────────
crack_with_hashcat() {
  local mode="$1" name="$2"
  info "Hashcat sınayır: ${BOLD}$name${NC} [mode $mode]"

  rm -f "$RESULT_FILE"

  # --quiet + stderr redirect — "Separator unmatched" kimi xətalar gizlədilir
  local hc_stderr
  hc_stderr=$(hashcat -m "$mode" "$HASH_FILE" "$WORDLIST" \
    --outfile "$RESULT_FILE" \
    --outfile-format 2 \
    --potfile-disable \
    --quiet --force -O 2>&1)

  # Hashcat kritik xəta verdisə (Separator, Token length...) keç
  if echo "$hc_stderr" | grep -qiE "Separator|Token|Invalid|No hashes"; then
    warn "  ↳ Bu format mode $mode üçün uyğun deyil, keçildi"
    return 1
  fi

  # Outfile-da nəticə varmı?
  if [[ -s "$RESULT_FILE" ]]; then
    FOUND=$(cat "$RESULT_FILE")
    ok "TAPILDI! [$name]  ${BOLD}$HASH${NC}  →  ${GREEN}${BOLD}$FOUND${NC}"
    return 0
  fi

  # Potfile yoxlaması — xətalı sətirləri filtr et
  local pot_line
  pot_line=$(hashcat -m "$mode" "$HASH_FILE" --show --quiet 2>/dev/null \
    | grep -v "Separator\|Token\|Invalid\|No hashes" \
    | grep ":" \
    | tail -n1)

  if [[ -n "$pot_line" ]]; then
    # Format: hash:plain — sadəcə plain hissəsini götür
    local plain="${pot_line#*:}"
    # Boş və ya xəta sətri deyilsə qəbul et
    if [[ -n "$plain" && ! "$plain" =~ (Separator|Token|Invalid) ]]; then
      FOUND="$plain"
      ok "POTFİLDƏ TAPILDI! [$name]  →  ${GREEN}${BOLD}$plain${NC}"
      return 0
    fi
  fi

  warn "  ↳ [$name] — tapılmadı"
  return 1
}

# ── John ilə sına ─────────────────────────────────────────
crack_with_john() {
  echo ""
  info "John the Ripper ilə sınayır (--format=auto)..."

  john "$HASH_FILE" --wordlist="$WORDLIST" --format=auto 2>/dev/null

  local result
  result=$(john --show "$HASH_FILE" 2>/dev/null | head -n1)

  if [[ "$result" == *":"* ]]; then
    local plain="${result#*:}"
    plain="${plain%%:*}"
    if [[ -n "$plain" ]]; then
      FOUND="$plain"
      ok "John ilə TAPILDI!  →  ${GREEN}${BOLD}$plain${NC}"
      return 0
    fi
  fi

  warn "John da tapa bilmədi"
  return 1
}

# ══════════════════════════════════════════════════════════
#  ANA AXIN
# ══════════════════════════════════════════════════════════
banner

[[ -z "$HASH" ]] && die "İstifadə: $0 <hash> [wordlist_yolu]"
[[ -f "$WORDLIST" ]] || die "Wordlist tapılmadı: $WORDLIST"

echo -e "${BOLD}Hədəf hash :${NC} $HASH"
echo -e "${BOLD}Wordlist   :${NC} $WORDLIST"
echo    "──────────────────────────────────────────"

check_deps

echo "$HASH" > "$HASH_FILE"

# Hash növlərini aşkarla
if command -v hashid &>/dev/null; then
  info "hashid ilə aşkarlama..."
  echo ""
  hashid -m "$HASH" 2>/dev/null
  echo ""
  parse_hashid_modes
fi

[[ ${#TYPE_MAP[@]} -eq 0 ]] && detect_manual

if [[ ${#TYPE_MAP[@]} -eq 0 ]]; then
  warn "Heç bir hashcat modu tapılmadı — birbaşa John istifadə ediləcək"
fi

echo "──────────────────────────────────────────"

# Hashcat ilə bütün tapılan mode-ları sına
if command -v hashcat &>/dev/null && [[ ${#TYPE_MAP[@]} -gt 0 ]]; then
  info "Hashcat ilə ${#TYPE_MAP[@]} növ sınanacaq..."
  echo ""
  for name in "${!TYPE_MAP[@]}"; do
    [[ -n "$FOUND" ]] && break
    crack_with_hashcat "${TYPE_MAP[$name]}" "$name"
  done
fi

# Tapılmadısa John ilə sına
if [[ -z "$FOUND" ]] && command -v john &>/dev/null; then
  crack_with_john
fi

# ── Final nəticə ──────────────────────────────────────────
echo ""
echo    "══════════════════════════════════════════"
if [[ -n "$FOUND" ]]; then
  echo -e "${GREEN}${BOLD}  ✓ NƏTİCƏ: $HASH  →  $FOUND${NC}"
else
  echo -e "${RED}${BOLD}  ✗ Hash crack edilə bilmədi${NC}"
  echo -e "${YELLOW}  İpuçları:"
  echo "  • Daha böyük wordlist: hashesorg.com-dan yüklə"
  echo "  • Rule attack: hashcat -m <mode> hash.txt rockyou.txt -r best64.rule"
  echo -e "  • Brute-force: hashcat -m <mode> -a 3 hash.txt ?a?a?a?a?a?a${NC}"
fi
echo "══════════════════════════════════════════"

rm -f "$HASH_FILE" "$RESULT_FILE"
