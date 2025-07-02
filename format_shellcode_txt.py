def extract_and_format_c_style_shellcode(txt_file: str, bytes_per_line: int = 16):
    # Ouvre le fichier texte contenant le shellcode brut
    with open(txt_file, "r") as f:
        lines = f.readlines()

    raw_bytes = ""

    # Parcourt chaque ligne du fichier
    for line in lines:
        line = line.strip()

        # Vérifie si la ligne commence et termine par des guillemets (")
        if line.startswith('"') and line.endswith('"'):
            line = line.strip('"')  # Enlève les guillemets
            raw_bytes += line.replace('"', '').replace('\n', '')  # Concatène les bytes en une chaîne brute

    # Conversion en paires hexadécimales (2 octets représentés par 4 caractères hex)
    hex_pairs = [raw_bytes[i:i+4] for i in range(0, len(raw_bytes), 4)]

    # Affichage du shellcode formaté en Python (b"..."), par blocs définis par bytes_per_line
    print("shellcode = (")
    for i in range(0, len(hex_pairs), bytes_per_line):
        chunk = hex_pairs[i:i+bytes_per_line]
        line = ''.join(chunk)
        print(f'    b"{line}"')
    print(")")

# Exemple d'utilisation (à exécuter directement comme script principal)
if __name__ == "__main__":
    extract_and_format_c_style_shellcode("shellcode.txt")
