import os
import hashlib
import sys
import signal
import base64
import random
import re
from termcolor import colored

def def_handler(sig, frame):
    print(colored("\n[!] Exiting...", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def print_banner():
    banner = """

.dP"Y8 88888  dP""b8 88""Yb 888888 888888 
`Ybo."   .dP dP   `" 88__dP 88__     88   
o.`Y8b o `Yb Yb      88"Yb  88""     88   
8bodP' YbodP  YboodP 88  Yb 888888   88   

Python Code Obfuscator
By tay

    """
    print(colored(banner, 'green'))

def xor_crypt(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def get_hidden_key():
    part1 = "dGhp"
    part2 = "zIGlz"
    part3 = "IFNFQ1JF"
    part4 = "VEtFWQ=="

    encoded_key = part1 + part2 + part3 + part4
    return base64.b64decode(encoded_key)

def generate_random_name(prefix):
    return f"{prefix}_{random.randint(1000, 9999)}"

def obfuscate_code(code):
    function_pattern = re.compile(r'\bdef (\w+)\(')
    variable_pattern = re.compile(r'^\s*(\w+)\s*=', re.MULTILINE)

    functions = function_pattern.findall(code)
    variables = variable_pattern.findall(code)

    rename_map = {}

    for func in functions:
        new_name = generate_random_name("tay_func")
        rename_map[func] = new_name

    for var in variables:
        if var not in rename_map and var not in ["True", "False", "None"]:
            new_name = generate_random_name("tay_var")
            rename_map[var] = new_name

    for old_name, new_name in rename_map.items():
        code = re.sub(rf'\b{old_name}\b', new_name, code)

    return code, rename_map

def encode_file_to_python_script():
    print_banner()
    input_file = input(colored("[+] Enter the path of the input file: ", 'green')).strip()
    output_file = input(colored("[+] Enter the name of the output file: ", 'green')).strip()

    if not os.path.exists(input_file):
        print(colored(f"[!] Error: No file named {input_file}.", 'red'))
        return

    try:
        key = get_hidden_key()

        with open(input_file, "r", encoding="utf-8") as file:
            original_code = file.read()

        obfuscated_code, rename_map = obfuscate_code(original_code)

        debug_file = "debug_obfuscated.py"
        with open(debug_file, "w", encoding="utf-8") as debug_out:
            debug_out.write(obfuscated_code)

        print(colored(f"\n[!] Obfuscated code saved in: {debug_file} - Check it before start.", 'green'))

        confirm = input(colored("[?] Is the code correct? (y/n): ", 'green')).strip().lower()
        if confirm != "y":
            print(colored("\n[!] Quitting the obfuscation.\n", 'red'))
            return

        os.remove(debug_file)
        data = obfuscated_code.encode("utf-8")
        encrypted_data = xor_crypt(data, key)

        with open(output_file, "w") as py_file:
            py_file.write("tay = b\"\"\n\n")

            for i in range(0, len(encrypted_data), 16):
                chunk = encrypted_data[i:i+16]
                encoded_chunk = "".join(f"\\x{byte:02x}" for byte in chunk)
                py_file.write(f"tay += b\"{encoded_chunk}\"\n")

            py_file.write("\nimport base64\n\n")

            py_file.write("def tay_1():\n")
            py_file.write("    return \"dGhp\"\n\n")

            py_file.write("def tay_2():\n")
            py_file.write("    return \"zIGlz\"\n\n")

            py_file.write("def tay_3():\n")
            py_file.write("    return \"IFNFQ1JF\"\n\n")

            py_file.write("def tay_4():\n")
            py_file.write("    return \"VEtFWQ==\"\n\n")

            py_file.write("def tay_5():\n")
            py_file.write("    tay_master = tay_1() + tay_2() + tay_3() + tay_4()\n")
            py_file.write("    return base64.b64decode(tay_master)\n\n")

            py_file.write("def tay_6(data):\n")
            py_file.write("    tay_master = tay_5()\n")
            py_file.write("    return bytes([data[i] ^ tay_master[i % len(tay_master)] for i in range(len(data))])\n\n")

            py_file.write("exec(tay_6(tay).decode('utf-8'))\n")

        print(colored(f"\n[+] Python file ofuscated: {output_file}", 'green'))

    except Exception as e:
        print(colored(f"\n[!] Error Processing the file: {e}", 'red'))

if __name__ == "__main__":
    encode_file_to_python_script()
