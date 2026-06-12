# 🔐 Hash Auto-Identifier & Cracker

A Bash-based hash cracking toolkit that automatically identifies hash types and attempts to crack them using **hashcat** and/or **John the Ripper**.

---

## Features

- **Auto-detection** — identifies hash type via `hashid` or built-in pattern matching
- **Multi-algorithm support** — MD5, SHA1, SHA256, SHA512, bcrypt, NTLM, phpass, and more
- **Salted hash cracking** — v2 adds full support for salted hashes (`-s <salt>`) across MD5/SHA1/SHA256/SHA512 variants
- **Dual-engine** — tries hashcat first, falls back to John the Ripper automatically
- **Smart skipping** — skips modes that require special formats (NetNTLMv1/v2, DCC, IPMI2, etc.) to avoid false errors
- **Potfile awareness** — checks hashcat's potfile for previously cracked hashes

---

## Requirements

| Tool | Install |
|------|---------|
| `hashcat` | `sudo apt install hashcat` |
| `john` | `sudo apt install john` |
| `hashid` | `pip3 install hashid` |

At least one of `hashcat` or `john` is required. `hashid` is optional but recommended for better type detection.

---

## Usage

### v1 — Basic (no salt support)

```bash
./hash-crack-v1.sh <hash> [wordlist]
```

### v2 — With salt support

```bash
# Without salt
./hash-crack-v2.sh <hash> [wordlist]

# With salt
./hash-crack-v2.sh <hash> [wordlist] -s <salt>
```

The `wordlist` argument defaults to `/usr/share/wordlists/rockyou.txt` if not specified.

---

## Examples

```bash
# Crack an MD5 hash using the default wordlist
./hash-crack-v2.sh 5f4dcc3b5aa765d61d8327deb882cf99

# Crack using a custom wordlist
./hash-crack-v2.sh 5f4dcc3b5aa765d61d8327deb882cf99 /path/to/wordlist.txt

# Crack a salted SHA256 hash
./hash-crack-v2.sh e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855 /usr/share/wordlists/rockyou.txt -s mysalt
```

---

## Supported Hash Types

| Length | Detected Types |
|--------|---------------|
| 32 hex | MD5, NTLM, MD4 |
| 40 hex | SHA1 |
| 64 hex | SHA256, SHA3-256 |
| 96 hex | SHA384 |
| 128 hex | SHA512, SHA3-512 |
| Prefix `$2a$`/`$2b$`/`$2y$` | bcrypt |
| Prefix `$1$` | md5crypt |
| Prefix `$5$` | sha256crypt |
| Prefix `$6$` | sha512crypt |
| Prefix `$P$` | phpass |

### Salted Modes (v2 only)

For each base hash length, the following salt ordering variants are tried:

- `hash(pass.salt)` and `hash(salt.pass)`
- Unicode variants
- HMAC variants (key = password or key = salt)

---

## How It Works

1. **Identify** — runs `hashid -m` to get candidate hashcat modes; falls back to regex/length-based detection if `hashid` is unavailable
2. **Crack (hashcat)** — iterates over all detected modes, running a dictionary attack with the provided wordlist
3. **Crack (John)** — if hashcat finds nothing, John the Ripper is tried with `--format=auto`
4. **Report** — prints the plaintext result or failure tips

---

## Output

On success:
```
[+] TAPILDI! [MD5]  5f4dcc3b5aa765d61d8327deb882cf99  →  password
══════════════════════════════════════════
  ✓ NƏTİCƏ: 5f4dcc3b5aa765d61d8327deb882cf99  →  password
══════════════════════════════════════════
```

On failure, actionable tips are printed:
```
  • Use a larger wordlist (e.g. hashesorg.com)
  • Rule attack: hashcat -m <mode> hash.txt rockyou.txt -r best64.rule
  • Brute-force: hashcat -m <mode> -a 3 hash.txt ?a?a?a?a?a?a
```

---

## File Versions

| File | Description |
|------|-------------|
| `hash-crack-v1.sh` | Original version — unsalted hashes only |
| `hash-crack-v2.sh` | Extended version — adds `-s <salt>` flag and salted mode table |

---

## Notes

- Scripts use `--potfile-disable` to avoid stale cache results during testing; remove this flag if you want hashcat to reuse previously cracked hashes.
- The `--force` flag is passed to hashcat to suppress driver warnings in virtualized environments. Remove it on bare-metal setups if you experience issues.
- Scripts are written for Bash and tested on Ubuntu/Debian systems.

---

