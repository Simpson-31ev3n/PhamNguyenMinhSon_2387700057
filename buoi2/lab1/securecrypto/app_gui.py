import tkinter as tk
from tkinter import filedialog, messagebox
from securecrypto import aes_utils


def encrypt():
    file = filedialog.askopenfilename()
    if not file:
        return
    pw = password_entry.get()
    if not pw:
        result_label.config(text="Vui lòng nhập Password!")
        return
    try:
        key = aes_utils.encrypt_file_aes(file, pw)
        result_label.config(text=f"Key: {key}")
    except Exception as e:
        messagebox.showerror("Error", f"Mã hóa thất bại: {e}")


def decrypt():
    file = filedialog.askopenfilename()
    if not file:
        return
    pw = password_entry.get()
    if not pw:
        result_label.config(text="Vui lòng nhập Password hoặc Key!")
        return
    try:
        out = aes_utils.decrypt_file_aes(file, pw)
        result_label.config(text=f"Output: {out}")
    except Exception as e:
        messagebox.showerror("Error", f"Giải mã thất bại: {e}")


if __name__ == '__main__':
    root = tk.Tk()
    root.title("SecureCrypto GUI")
    password_entry = tk.Entry(root, show="*")
    password_entry.pack(pady=5)
    tk.Button(root, text="Encrypt", command=encrypt).pack(pady=2)
    tk.Button(root, text="Decrypt", command=decrypt).pack(pady=2)
    result_label = tk.Label(root, text="", wraplength=350)
    result_label.pack(pady=5)
    root.mainloop()

