import tkinter as tk
from tkinter import messagebox, Menu, Toplevel, END
from tkinter import ttk
import sqlite3
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import random
import string
import os
import threading
import atexit
import signal

# New Color Scheme
BACKGROUND_COLOR = "#2E3440"  # Dark grey-blue
ENTRY_BG_COLOR = "#3B4252"  # Grey-blue
BUTTON_BG_COLOR = "#88C0D0"  # Soft cyan
BUTTON_FG_COLOR = "#2E3440"  # Dark grey-blue
TITLE_COLOR = "#A3BE8C"  # Soft green
LISTBOX_BG_COLOR = "#D08770"  # Soft orange
TEXT_COLOR = "#ECEFF4"  # Off-white

# Database setup
conn = sqlite3.connect('passwords.db')
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS master_password (
        id INTEGER PRIMARY KEY,
        salt TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY,
        website TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')

conn.commit()

# Initialize Argon2 password hasher
ph = PasswordHasher()

# Hashing function with Argon2
def hash_password(password, salt):
    return ph.hash(password + salt)

# Verify Argon2 hash
def verify_password(hash, password, salt):
    try:
        ph.verify(hash, password + salt)
        return True
    except:
        return False

# Generate a key based on the master password using PBKDF2HMAC
def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)

# Encrypt data
def encrypt_data(key, data):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

# Decrypt data
def decrypt_data(key, encrypted_data):
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

# Generate a random password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    random_password = ''.join(random.choice(characters) for i in range(length))
    return random_password

# Check if master password is set
def check_master_password():
    c.execute('SELECT * FROM master_password')
    return c.fetchone() is not None

# Cleanup function to ensure the application stops
def cleanup(signum=None, frame=None):
    print("Cleaning up and closing the application.")
    conn.close()
    root.quit()

# Register cleanup function
atexit.register(cleanup)
signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)

# Custom dialog functions
def custom_dialog(title, prompt, show=''):
    dialog = Toplevel(root)
    dialog.title(title)
    dialog.geometry("300x150")
    dialog.config(bg=BACKGROUND_COLOR)

    ttk.Label(dialog, text=prompt, background=BACKGROUND_COLOR, foreground=TEXT_COLOR).pack(pady=10)
    entry = ttk.Entry(dialog, show=show)
    entry.pack(pady=5)

    def on_ok():
        dialog.result = entry.get()
        dialog.destroy()

    def on_cancel():
        dialog.result = None
        dialog.destroy()

    ttk.Button(dialog, text="OK", command=on_ok, style="TButton").pack(side="left", padx=(40, 10), pady=10)
    ttk.Button(dialog, text="Cancel", command=on_cancel, style="TButton").pack(side="right", padx=(10, 40), pady=10)

    dialog.transient(root)
    dialog.grab_set()
    root.wait_window(dialog)
    return dialog.result

# GUI setup
root = tk.Tk()
root.title("Password Manager")
root.geometry("600x400")
root.config(bg=BACKGROUND_COLOR)

style = ttk.Style()
style.theme_use("clam")

style.configure("TFrame", background=BACKGROUND_COLOR)
style.configure("TLabel", background=BACKGROUND_COLOR, font=("Helvetica", 12), foreground=TEXT_COLOR)
style.configure("TButton", background=BUTTON_BG_COLOR, foreground=BUTTON_FG_COLOR, font=("Helvetica", 12))
style.configure("TEntry", fieldbackground=ENTRY_BG_COLOR, font=("Helvetica", 12))
style.configure("TListbox", background=LISTBOX_BG_COLOR, font=("Helvetica", 12))
style.configure("TMenu", background=BUTTON_BG_COLOR, foreground=BUTTON_FG_COLOR, font=("Helvetica", 12))
style.configure("TDialog", background=BACKGROUND_COLOR, foreground=TEXT_COLOR, font=("Helvetica", 12))

def set_master_password():
    password = custom_dialog("Master Password", "Set your master password (minimum 12 characters):", show='*')
    if password is None or len(password) < 12:
        messagebox.showerror("Error", "Password must be at least 12 characters long.")
        return
    salt = os.urandom(16).hex()
    hashed_password = hash_password(password, salt)
    c.execute('INSERT INTO master_password (salt, password) VALUES (?, ?)', (salt, hashed_password))
    conn.commit()
    messagebox.showinfo("Success", "Master password set successfully!")
    open_password_manager(generate_key(password, salt))

def verify_master_password():
    password = custom_dialog("Master Password", "Enter your master password:", show='*')
    if password is None:
        return
    c.execute('SELECT salt, password FROM master_password')
    row = c.fetchone()
    if row:
        salt, hashed_password = row
        if verify_password(hashed_password, password, salt):
            key = generate_key(password, salt)
            open_password_manager(key)
        else:
            messagebox.showerror("Error", "Incorrect master password!")
    else:
        messagebox.showerror("Error", "Master password not set!")

def open_password_manager(key):
    # Clear the root window
    for widget in root.winfo_children():
        widget.destroy()

    # Configure the root window
    root.geometry("800x600")
    root.resizable(True, True)
    root.config(bg=BACKGROUND_COLOR)

    def add_password():
        website = custom_dialog("Website", "Enter the website:")
        username = custom_dialog("Username", "Enter the username:")
        password = custom_dialog("Password", "Enter the password:")
        if website is None or username is None or password is None:
            return
        encrypted_username = encrypt_data(key, username)
        encrypted_password = encrypt_data(key, password)
        c.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)', (website, encrypted_username, encrypted_password))
        conn.commit()
        messagebox.showinfo("Success", "Password added successfully!")
        update_password_list()

    def generate_password():
        length = custom_dialog("Password Length", "Enter the desired password length:")
        if length is None or not length.isdigit() or int(length) < 12:
            messagebox.showerror("Error", "Password length must be a number and at least 12.")
            return
        password = generate_random_password(int(length))
        messagebox.showinfo("Generated Password", f"Generated Password: {password}")

    def update_password_list():
        password_list.delete(0, END)
        c.execute('SELECT id, website FROM passwords')
        rows = c.fetchall()
        for row in rows:
            password_list.insert(END, f"ID: {row[0]} | Website: {row[1]}")

    def search_passwords():
        search_query = custom_dialog("Search", "Enter website to search:")
        if search_query is None:
            return
        passwords_window = Toplevel(root)
        passwords_window.title("Search Results")
        passwords_window.geometry("800x400")
        passwords_window.config(bg=BACKGROUND_COLOR)

        search_list = tk.Listbox(passwords_window, width=80, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR)
        search_list.pack(side="left", fill="both", expand=True)

        search_scrollbar = tk.Scrollbar(passwords_window)
        search_scrollbar.pack(side="right", fill="y")

        search_list.config(yscrollcommand=search_scrollbar.set)
        search_scrollbar.config(command=search_list.yview)

        c.execute('SELECT id, website FROM passwords WHERE website LIKE ?', (f'%{search_query}%',))
        rows = c.fetchall()
        for row in rows:
            search_list.insert(END, f"ID: {row[0]} | Website: {row[1]}")

    def delete_password():
        delete_id = custom_dialog("Delete Entry", "Enter the ID of the entry to delete:")
        if delete_id is None or not delete_id.isdigit():
            return
        c.execute('DELETE FROM passwords WHERE id = ?', (delete_id,))
        conn.commit()
        messagebox.showinfo("Success", "Password entry deleted successfully!")
        update_password_list()

    def replace_password(entry_id):
        new_password = custom_dialog("New Password", "Enter the new password:")
        if new_password is None:
            return
        encrypted_password = encrypt_data(key, new_password)
        c.execute('UPDATE passwords SET password = ? WHERE id = ?', (encrypted_password, entry_id))
        conn.commit()
        messagebox.showinfo("Success", "Password updated successfully!")
        update_password_list()

    def replace_username(entry_id):
        new_username = custom_dialog("New Username", "Enter the new username:")
        if new_username is None:
            return
        encrypted_username = encrypt_data(key, new_username)
        c.execute('UPDATE passwords SET username = ? WHERE id = ?', (encrypted_username, entry_id))
        conn.commit()
        messagebox.showinfo("Success", "Username updated successfully!")
        update_password_list()

    def replace_website(entry_id):
        new_website = custom_dialog("New Website", "Enter the new website:")
        if new_website is None:
            return
        c.execute('UPDATE passwords SET website = ? WHERE id = ?', (new_website, entry_id))
        conn.commit()
        messagebox.showinfo("Success", "Website updated successfully!")
        update_password_list()

    def view_password_details(event):
        selected_item = password_list.get(password_list.curselection())
        entry_id = selected_item.split("|")[0].split(":")[1].strip()
        
        c.execute('SELECT * FROM passwords WHERE id = ?', (entry_id,))
        entry = c.fetchone()
        
        decrypted_username = decrypt_data(key, entry[2])
        decrypted_password = decrypt_data(key, entry[3])
        
        details_window = Toplevel(root)
        details_window.title("Password Details")
        details_window.geometry("400x400")
        details_window.config(bg=BACKGROUND_COLOR)
        
        def copy_to_clipboard(text):
            root.clipboard_clear()
            root.clipboard_append(text)
            messagebox.showinfo("Copied", f"Copied to clipboard: {text}")

        ttk.Label(details_window, text=f"Website: {entry[1]}", style="TLabel").grid(row=0, column=0, pady=5)
        ttk.Button(details_window, text="Copy Website", command=lambda: copy_to_clipboard(entry[1]), style="TButton").grid(row=0, column=1, pady=5)
        ttk.Button(details_window, text="Replace Website", command=lambda: replace_website(entry_id), style="TButton").grid(row=1, column=0, columnspan=2, pady=5)

        ttk.Label(details_window, text=f"Username: {decrypted_username}", style="TLabel").grid(row=2, column=0, pady=5)
        ttk.Button(details_window, text="Copy Username", command=lambda: copy_to_clipboard(decrypted_username), style="TButton").grid(row=2, column=1, pady=5)
        ttk.Button(details_window, text="Replace Username", command=lambda: replace_username(entry_id), style="TButton").grid(row=3, column=0, columnspan=2, pady=5)

        ttk.Label(details_window, text=f"Password: {decrypted_password}", style="TLabel").grid(row=4, column=0, pady=5)
        ttk.Button(details_window, text="Copy Password", command=lambda: copy_to_clipboard(decrypted_password), style="TButton").grid(row=4, column=1, pady=5)
        ttk.Button(details_window, text="Replace Password", command=lambda: replace_password(entry_id), style="TButton").grid(row=5, column=0, columnspan=2, pady=5)

        # Center the details window
        root.update_idletasks()
        x = (root.winfo_screenwidth() // 2) - (details_window.winfo_reqwidth() // 2)
        y = (root.winfo_screenheight() // 2) - (details_window.winfo_reqheight() // 2)
        details_window.geometry(f"+{x}+{y}")

        # Auto-close the window after 3 seconds
        threading.Timer(3.0, details_window.destroy).start()

    menu = Menu(root)
    root.config(menu=menu)

    file_menu = Menu(menu, tearoff=0, bg=BUTTON_BG_COLOR, fg=BUTTON_FG_COLOR, font=("Helvetica", 12))
    menu.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Add Password", command=add_password)
    file_menu.add_command(label="Generate Password", command=generate_password)
    file_menu.add_command(label="Search Passwords", command=search_passwords)
    file_menu.add_command(label="Delete Password", command=delete_password)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)

    # Create a frame for the password list
    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True, padx=10, pady=10)

    # Create a listbox with a scrollbar
    password_list = tk.Listbox(frame, width=100, height=25, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR)
    password_list.pack(side="left", fill="both", expand=True)
    password_list.bind('<<ListboxSelect>>', view_password_details)

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side="right", fill="y")

    password_list.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=password_list.yview)

    update_password_list()

if check_master_password():
    verify_master_password()
else:
    set_master_password()

root.mainloop()

