# S3cret Python Code Obfuscator & Encryptor

## Description
This is a Python code obfuscator and encryptor that allows obfuscating variables and functions in a Python script before encrypting it using a hidden XOR key.

---

## Features
- **Code obfuscation**: Renames variables and functions to make them harder to understand.
- **XOR encryption**: Protects code from direct inspection.
- **Automated structure**: Detects imports and elements that should not be replaced.

---

## Installation
Before running the obfuscator, make sure you have the necessary dependencies installed. You can install them by running:

```sh
pip install termcolor
```

---

## Usage
To run the obfuscator and encryptor, use the following command:

```sh
python obfuscator.py --input <script.py> --output <output.py> [--obfuscate]
```

### Arguments
| Argument       | Description |
|---------------|-------------|
| `--input`      | Path to the Python script to be obfuscated and/or encrypted. |
| `--output`     | Path where the encrypted script will be saved. |
| `--obfuscate`  | (Optional) Enables code obfuscation before encryption. |

### Example Usage
If you only want to encrypt a file without changing variable or function names:

```sh
python obfuscator.py --input script.py --output script_enc.py
```

If you want to obfuscate the code before encrypting it:

```sh
python obfuscator.py --input script.py --output script_enc.py --obfuscate
```

---

## How It Works
1. **Loads the source code from the specified file**.
2. **(Optional) Performs obfuscation of variable and function names**.
3. **Encrypts the code using XOR with a hidden secret key**.
4. **Saves the encrypted code in a new output file**.
5. **The encrypted code is executed using `exec()` after decryption**.

---

## Notes
- Obfuscation may affect code functionality if critical variables are modified.
- It is recommended to review the `debug_obfuscated.py` file before proceeding with encryption.
- **This script is not an absolute security mechanism but an additional layer of protection for source code**.

---

