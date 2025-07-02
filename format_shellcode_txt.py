# format_c_shellcode_txt.py

def extract_and_format_c_style_shellcode(txt_file: str, bytes_per_line: int = 16):
    with open(txt_file, "r") as f:
        lines = f.readlines()

    raw_bytes = ""

    for line in lines:
        line = line.strip()

        if line.startswith('"') and line.endswith('"'):
            line = line.strip('"')
            raw_bytes += line.replace('"', '').replace('\n', '')

    # Convert to Python shellcode block
    hex_pairs = [raw_bytes[i:i+4] for i in range(0, len(raw_bytes), 4)]
    print("shellcode = (")
    for i in range(0, len(hex_pairs), bytes_per_line):
        chunk = hex_pairs[i:i+bytes_per_line]
        line = ''.join(chunk)
        print(f'    b"{line}"')
    print(")")

# Usage
if __name__ == "__main__":
    extract_and_format_c_style_shellcode("shellcode.txt")
