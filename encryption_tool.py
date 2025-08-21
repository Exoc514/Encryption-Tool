import tkinter as tk
from tkinter import ttk, messagebox
import base64
import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --------- AES Helper Functions ----------
def aes_encrypt(message, key):
    key = key.ljust(32)[:32].encode()  # make 32 bytes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(cipher_text, key):
    key = key.ljust(32)[:32].encode()
    raw = base64.b64decode(cipher_text)
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

# --------- RSA Helper Functions ----------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_rsa_keys()

def rsa_encrypt(message):
    encrypted_bytes = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return base64.b64encode(encrypted_bytes).decode()

def rsa_decrypt(cipher_text):
    encrypted_bytes = base64.b64decode(cipher_text)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return decrypted.decode()

# --------- Logic ----------
def encrypt_message():
    message = text1.get("1.0", tk.END).strip()
    key = code.get()
    algo = algo_choice.get()

    if not message:
        messagebox.showerror("Error", "Enter a message first!")
        return

    start = time.time()
    if algo == "AES":
        if not key:
            messagebox.showerror("Error", "Enter a secret key for AES")
            return
        encrypted = aes_encrypt(message, key)
    else:  # RSA
        encrypted = rsa_encrypt(message)
    end = time.time()

    text2.delete("1.0", tk.END)
    text2.insert(tk.END, encrypted)
    messagebox.showinfo("Success", f"{algo} encryption finished in {end-start:.4f} sec")

def decrypt_message():
    cipher_text = text2.get("1.0", tk.END).strip()
    key = code.get()
    algo = algo_choice.get()

    if not cipher_text:
        messagebox.showerror("Error", "Enter ciphertext first!")
        return

    try:
        start = time.time()
        if algo == "AES":
            if not key:
                messagebox.showerror("Error", "Enter the same AES key used for encryption")
                return
            decrypted = aes_decrypt(cipher_text, key)
        else:  # RSA
            decrypted = rsa_decrypt(cipher_text)
        end = time.time()

        text3.delete("1.0", tk.END)
        text3.insert(tk.END, decrypted)
        messagebox.showinfo("Success", f"{algo} decryption finished in {end-start:.4f} sec")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def reset_fields():
    text1.delete("1.0", tk.END)
    text2.delete("1.0", tk.END)
    text3.delete("1.0", tk.END)
    code.set("")
    algo_choice.set("AES")

# --------- GUI Setup ----------
def main_screen():
    global text1, text2, text3, code, algo_choice

    screen = tk.Tk()
    screen.geometry("650x700")
    screen.title("🔐 Cute Encryption & Decryption Tool")
    screen.configure(bg="#1e293b")  # dark blue-gray background

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TButton",
                    font=("Arial", 12, "bold"),
                    padding=8,
                    relief="flat",
                    foreground="black",
                    background="#e5e6e8")
    style.map("TButton",
              background=[("active", "#e5e6e8")])

    # Title
    tk.Label(screen, text="🔒 Secure Message Locker", font=("Arial", 20, "bold"),
             fg="white", bg="#1e293b").pack(pady=15)

    # Message input
    tk.Label(screen, text="Enter your message:", font=("Arial", 13),
             fg="white", bg="#1e293b").pack()
    text1 = tk.Text(screen, font=("Arial", 12), height=5, width=70, wrap="word", bd=3, relief="groove",bg="white", fg="black")
    text1.pack(pady=5)

    # Secret key
    tk.Label(screen, text="Secret key (for AES only):", font=("Arial", 13),
             fg="white", bg="#1e293b").pack()
    code = tk.StringVar()
    tk.Entry(screen, textvariable=code, show="*", font=("Arial", 12), width=30, bd=3, relief="groove",bg="white",fg="black").pack(pady=5)

    # Algorithm
    tk.Label(screen, text="Choose Algorithm:", font=("Arial", 13),
             fg="white", bg="#1e293b").pack()
    algo_choice = tk.StringVar(value="AES")
    algo_menu = ttk.Combobox(screen, textvariable=algo_choice, values=["AES", "RSA"], font=("Arial", 12), state="readonly")
    algo_menu.pack(pady=5)

    # Buttons
    button_frame = tk.Frame(screen, bg="#1e293b")
    button_frame.pack(pady=10)

    ttk.Button(button_frame, text="🔑 ENCRYPT", command=encrypt_message).grid(row=0, column=0, padx=10)
    ttk.Button(button_frame, text="🔓 DECRYPT", command=decrypt_message).grid(row=0, column=1, padx=10)
    ttk.Button(button_frame, text="♻ RESET", command=reset_fields).grid(row=0, column=2, padx=10)

    # Cipher text
    tk.Label(screen, text="Cipher Text:", font=("Arial", 13),
             fg="white", bg="#1e293b").pack()
    text2 = tk.Text(screen, font=("Arial", 12), height=5, width=70, wrap="word", bd=3, relief="groove",bg="white",fg="black")
    text2.pack(pady=5)

    # Decrypted text
    tk.Label(screen, text="Decrypted Text:", font=("Arial", 13),
             fg="white", bg="#1e293b").pack()
    text3 = tk.Text(screen, font=("Arial", 12), height=5, width=70, wrap="word", bd=3, relief="groove",bg="white",fg="black")
    text3.pack(pady=5)

    screen.mainloop()

main_screen()
