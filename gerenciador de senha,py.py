# PASSWORD MANAGER PROFISSIONAL
# Autor: Bruno Grola Gonçalves
# Uso educacional / portfólio

import os
import json
import base64
import hashlib
import secrets
import string
import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet

VAULT_FILE = "vault.dat"
BACKUP_FILE = "vault_backup.dat"

# ---------------- SEGURANÇA ----------------
def gerar_chave(senha_mestra, salt):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        senha_mestra.encode(),
        salt,
        390000
    )
    return base64.urlsafe_b64encode(key)


def gerar_salt():
    return os.urandom(16)


# ---------------- PASSWORD GENERATOR ----------------
def gerar_senha_forte(tamanho=16):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(caracteres) for _ in range(tamanho))


# ---------------- VAULT ----------------
def salvar_vault(vault, fernet, salt):
    data = {
        "salt": base64.b64encode(salt).decode(),
        "vault": vault
    }
    encrypted = fernet.encrypt(json.dumps(data).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)


def carregar_vault(fernet):
    if not os.path.exists(VAULT_FILE):
        return {}, gerar_salt()
    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        data = json.loads(decrypted.decode())
        salt = base64.b64decode(data["salt"])
        return data["vault"], salt
    except:
        messagebox.showerror("Erro", "Senha mestra incorreta")
        exit()


# ---------------- BACKUP ----------------
def criar_backup():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "rb") as src, open(BACKUP_FILE, "wb") as dst:
            dst.write(src.read())
        messagebox.showinfo("Backup", "Backup criptografado criado!")


# ---------------- INTERFACE ----------------
class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Manager")
        self.vault = {}
        self.salt = gerar_salt()

        self.senha_mestra = simpledialog.askstring(
            "Senha Mestra",
            "Digite sua senha mestra:",
            show='*'
        )

        chave = gerar_chave(self.senha_mestra, self.salt)
        self.fernet = Fernet(chave)
        self.vault, self.salt = carregar_vault(self.fernet)

        self.build_ui()

    def build_ui(self):
        tk.Button(self.root, text="Adicionar", width=20, command=self.add).pack(pady=5)
        tk.Button(self.root, text="Listar", width=20, command=self.listar).pack(pady=5)
        tk.Button(self.root, text="Gerar Senha", width=20, command=self.gerar).pack(pady=5)
        tk.Button(self.root, text="Remover", width=20, command=self.remover).pack(pady=5)
        tk.Button(self.root, text="Backup", width=20, command=criar_backup).pack(pady=5)

    def add(self):
        servico = simpledialog.askstring("Serviço", "Nome do serviço")
        usuario = simpledialog.askstring("Usuário", "Usuário")
        senha = simpledialog.askstring("Senha", "Senha")

        if servico:
            self.vault[servico] = {"usuario": usuario, "senha": senha}
            salvar_vault(self.vault, self.fernet, self.salt)
            messagebox.showinfo("Sucesso", "Senha salva")

    def listar(self):
        if not self.vault:
            messagebox.showinfo("Vault", "Nenhuma senha salva")
            return
        texto = "\n".join(self.vault.keys())
        messagebox.showinfo("Serviços", texto)

    def gerar(self):
        senha = gerar_senha_forte()
        messagebox.showinfo("Senha Gerada", senha)

    def remover(self):
        servico = simpledialog.askstring("Remover", "Serviço")
        if servico in self.vault:
            del self.vault[servico]
            salvar_vault(self.vault, self.fernet, self.salt)
            messagebox.showinfo("Removido", "Senha removida")


# ---------------- MAIN ----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
