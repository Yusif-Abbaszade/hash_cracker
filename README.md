content = """# Hash Auto-Identifier & Cracker

A simple, automated Bash-based wrapper for popular password cracking tools (`hashcat` and `john`) that facilitates hash identification and automated cracking attempts. It is designed to speed up the reconnaissance and initial cracking phase for security researchers and CTF participants.

## Features

- **Automated Identification**: Uses `hashid` to identify the hash type, with a fallback to manual identification based on string length and format patterns.
- **Automated Cracking**:
    - **Hashcat Integration**: Cycles through identified modes to attempt cracking.
    - **John the Ripper Integration**: Serves as a reliable fallback if Hashcat fails or if the hash type is unsupported by the detected Hashcat mode.
- **Salt Support**: Version 2 introduces support for salted hashes, allowing for specific salt-handling modes (e.g., `pass.salt`, `salt.pass`, `HMAC`).
- **User-Friendly**: Provides clear output, visual feedback (colored output), and helpful tips if cracking attempts are unsuccessful.

## Prerequisites

- **Tools**: `hashcat`, `john` (John the Ripper), `hashid`.
- **Operating System**: Linux (Bash environment).
- **Wordlists**: A wordlist file (default: `/usr/share/wordlists/rockyou.txt`).

### Installation of Dependencies (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install hashcat john
pip3 install hashid
