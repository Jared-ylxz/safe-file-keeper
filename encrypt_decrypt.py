#!/usr/bin/env python3
import os
import sys
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass
import subprocess
import hashlib

# 配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SALT_PATH = os.path.join(BASE_DIR, ".vault_salt")
FILES_BASE_PATH = os.path.join(BASE_DIR, "encrypted_files")
TMP_FILE = os.path.join(FILES_BASE_PATH, ".temp_vault_edit")


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=100000, dklen=32)


def encrypt(data: str, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))
    return cipher.nonce + tag + ciphertext


def decrypt(encrypted_data: bytes, key: bytes) -> str:
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def get_or_create_salt():
    if os.path.exists(SALT_PATH):
        with open(SALT_PATH, "rb") as f:
            salt = f.read()
    else:
        salt = get_random_bytes(16)
        with open(SALT_PATH, "wb") as f:
            f.write(salt)
    return salt


def edit_in_vim(content: str) -> str:
    try:
        with open(TMP_FILE, "w") as f:
            f.write(content)
        subprocess.call(["vim", TMP_FILE])
        with open(TMP_FILE, "r") as f:
            return f.read()
    finally:
        if os.path.exists(TMP_FILE):
            os.unlink(TMP_FILE)


def get_encrypted_path(input_path: str) -> str:
    """将输入路径转换为加密文件路径（保留目录结构）"""

    # 移除路径开头的~和/
    clean_path = os.path.expanduser(input_path).lstrip("./").lstrip("/")
    # 组合最终路径
    enc_path = os.path.join(FILES_BASE_PATH, f"{clean_path}.enc")

    # 确保目录存在
    # os.makedirs(os.path.dirname(enc_path), exist_ok=True)
    return enc_path


def handle_file(input_path: str, action: str):
    enc_path = get_encrypted_path(input_path)
    salt = get_or_create_salt()
    key = derive_key(getpass("Enter vault password: "), salt)
    # todo 设置密码要两次

    # todo 不需要这个参数
    if action == "edit":
        content = ""
        if os.path.exists(enc_path):
            with open(enc_path, "rb") as f:
                content = decrypt(f.read(), key)

        new_content = edit_in_vim(content)
        with open(enc_path, "wb") as f:
            f.write(encrypt(new_content, key))
        print(f"📁 Encrypted file saved to:\n{enc_path}")

    elif action == "view":
        if os.path.exists(enc_path):
            with open(enc_path, "rb") as f:
                print(decrypt(f.read(), key))
        else:
            print(f"❌ Encrypted file not found:\n{enc_path}")


def main():
    parser = argparse.ArgumentParser(
        description="🔒 Secure File Vault (Supports Subdirectories)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  Edit file: python vault.py travel/japan.txt edit\n"
               "  View file: python vault.py work/projects/secret.txt view"
    )
    parser.add_argument(
        "input_path",
        help="File path (relative or absolute)\n"
             "e.g. ~/travel/japan.txt or work/secret.txt"
    )
    # todo 删除
    parser.add_argument(
        "action",
        choices=["edit", "view"],
        help="Operation:\n"
             "  edit - Edit and encrypt\n"
             "  view - Decrypt and view"
    )

    if len(sys.argv) < 3:
        parser.print_help()
        sys.exit(1)

    try:
        args = parser.parse_args()
        handle_file(args.input_path, args.action)
    except ValueError:
        print(f"🔥 Incorrect password.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"🔥 Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
