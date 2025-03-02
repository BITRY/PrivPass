import tkinter as tk
from tkinter import messagebox, Menu, Toplevel, END
from tkinter import ttk
import sqlite3
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64
import random
import string
import os
import atexit
import signal
import time
import csv
from datetime import datetime
import shutil

# =========================
#   Version: 4.2.2.1
#   Product Name: PrivPass(R)
# =========================

# -------------------------
#   Color Theme / Style
# -------------------------
DARK_BG_COLOR = "#1E1E1E"
DARK_ENTRY_BG = "#2C2C2C"
DARK_LIST_BG  = "#333333"
ACCENT_COLOR  = "#FFD700"
BUTTON_BG     = "#555555"
BUTTON_FG     = "#FFFFFF"

# -------------------------
#   Database Setup
# -------------------------
DB_FILENAME = 'passwords.db'
conn = sqlite3.connect(DB_FILENAME)
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

try:
    c.execute('SELECT notes FROM passwords LIMIT 1')
except sqlite3.OperationalError:
    c.execute('ALTER TABLE passwords ADD COLUMN notes TEXT')

try:
    c.execute('SELECT modified_at FROM passwords LIMIT 1')
except sqlite3.OperationalError:
    c.execute('ALTER TABLE passwords ADD COLUMN modified_at TEXT')

conn.commit()

# -------------------------
#   Cryptographic Setup
# -------------------------
ph = PasswordHasher()

def hash_password(password, salt):
    return ph.hash(password + salt)

def verify_password(stored_hash, password, salt):
    try:
        ph.verify(stored_hash, password + salt)
        return True
    except:
        return False

def generate_key(master_password, salt):
    """Derive a 256-bit key from (master_password + salt) for Fernet."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_data(key, data):
    try:
        f = Fernet(key)
        return f.encrypt(data.encode()).decode()
    except Exception as e:
        messagebox.showerror("Encryption Error", f"Failed to encrypt data:\n{e}")
        return None

def decrypt_data(key, enc_data):
    try:
        f = Fernet(key)
        return f.decrypt(enc_data.encode()).decode()
    except (InvalidToken, Exception) as e:
        messagebox.showerror("Decryption Error", f"Failed to decrypt data:\n{e}")
        return None

# -------------------------
#   Password Generation
# -------------------------
def generate_random_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def generate_password():
    length_str = pointer_centered_dialog(root, "Password Generator", "Enter desired password length (min 12):")
    if length_str is None or not length_str.isdigit() or int(length_str) < 12:
        messagebox.showerror("Error", "Password length must be ≥ 12.")
        return
    pw = generate_random_password(int(length_str))
    messagebox.showinfo("Generated Password", f"Generated Password:\n\n{pw}")

# -------------------------
#   Utility Functions
# -------------------------
def check_master_password():
    c.execute('SELECT * FROM master_password')
    return c.fetchone() is not None

def reencrypt_database(old_key, new_key):
    """When changing master password, re-encrypt with new key."""
    c.execute('SELECT id, username, password, notes FROM passwords')
    for row in c.fetchall():
        row_id, old_enc_u, old_enc_p, old_enc_n = row
        dec_u = decrypt_data(old_key, old_enc_u)
        dec_p = decrypt_data(old_key, old_enc_p)
        dec_n = decrypt_data(old_key, old_enc_n) if old_enc_n else None
        if dec_u and dec_p:
            new_enc_u = encrypt_data(new_key, dec_u)
            new_enc_p = encrypt_data(new_key, dec_p)
            new_enc_n = encrypt_data(new_key, dec_n) if dec_n else None
            c.execute('''
                UPDATE passwords
                SET username=?, password=?, notes=?
                WHERE id=?
            ''',(new_enc_u,new_enc_p,new_enc_n,row_id))
            conn.commit()

def backup_database():
    t = datetime.now().strftime("%Y%m%d_%H%M%S")
    fn = f"passwords_backup_{t}.db"
    try:
        shutil.copyfile(DB_FILENAME, fn)
        messagebox.showinfo("Backup DB", f"Database backed up to {fn}")
    except Exception as e:
        messagebox.showerror("Backup Error", f"Could not back up the database:\n{e}")

def check_password_strength(password):
    score = 0
    if len(password) >= 12:
        score += 1
    has_digit = any(ch.isdigit() for ch in password)
    has_upper = any(ch.isupper() for ch in password)
    has_spec  = any(ch in string.punctuation for ch in password)
    score += sum([has_digit, has_upper, has_spec])
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Moderate"
    else:
        return "Strong"

def cleanup(signum=None, frame=None):
    print("Cleaning up and closing the application.")
    conn.close()
    root.quit()

atexit.register(cleanup)
signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)

# -------------------------
#   Pointer-Centered Windows
# -------------------------
def pointer_centered_dialog(parent, title, prompt, show='', auto_close_seconds=60):
    """A short input dialog near the mouse pointer."""
    d = tk.Toplevel(parent)
    d.title(title)
    d.config(bg=DARK_BG_COLOR)
    d.resizable(False, False)
    d.transient(parent)
    d.grab_set()

    width = 500
    height= 220

    px= parent.winfo_pointerx()
    py= parent.winfo_pointery()
    x= px-(width//2)
    y= py-(height//2)
    d.geometry(f"{width}x{height}+{x}+{y}")

    frm= ttk.Frame(d, style="TFrame")
    frm.pack(padx=20, pady=20)

    lbl= ttk.Label(frm, text=prompt, background=DARK_BG_COLOR, foreground=ACCENT_COLOR)
    lbl.pack(pady=(0,5))

    entry= ttk.Entry(frm, show=show, width=40)
    entry.pack(pady=5)

    d.result= None

    def on_ok():
        val= entry.get().strip()
        if not val:
            messagebox.showwarning("Input Error","Field cannot be empty!")
            return
        d.result= val
        d.destroy()

    def on_cancel():
        d.result= None
        d.destroy()

    d.bind("<Return>", lambda e: on_ok())
    d.bind("<Escape>", lambda e: on_cancel())

    bf = ttk.Frame(frm)
    bf.pack(pady=15)
    okb= ttk.Button(bf, text="OK", command=on_ok, style="Accent.TButton")
    okb.pack(side="left", padx=(0,20))
    cb= ttk.Button(bf, text="Cancel", command=on_cancel, style="Accent.TButton")
    cb.pack(side="right")

    if auto_close_seconds>0:
        d.after(auto_close_seconds*1000, d.destroy)

    entry.focus_set()
    parent.wait_window(d)
    return d.result

def pointer_centered_window(parent, child):
    """Auto-size 'child', place near mouse pointer."""
    child.resizable(False,False)
    child.update_idletasks()
    w= child.winfo_reqwidth()
    h= child.winfo_reqheight()
    px= parent.winfo_pointerx()
    py= parent.winfo_pointery()
    x= px-(w//2)
    y= py-(h//2)
    child.geometry(f"{w}x{h}+{x}+{y}")

# -------------------------
#   Splash Screen
# -------------------------
def show_splash_screen():
    """Display 550×650 near the pointer, ~5s progress bar."""
    w=550
    h=650
    px= root.winfo_pointerx()
    py= root.winfo_pointery()
    x= px-(w//2)
    y= py-(h//2)

    splash= tk.Toplevel(root)
    splash.title("Loading PrivPass...")
    splash.config(bg=DARK_BG_COLOR)
    splash.geometry(f"{w}x{h}+{x}+{y}")
    splash.resizable(False,False)

    frm= ttk.Frame(splash, style="TFrame")
    frm.pack(padx=20,pady=20)

    try:
        spimg= tk.PhotoImage(file="privpass.privpic")
    except Exception as e:
        messagebox.showwarning("Splash Image Error", f"Could not load 'privpass.privpic':\n{e}")
        spimg= None

    if spimg:
        lbl_img= ttk.Label(frm, image=spimg, style="TLabel", background=DARK_BG_COLOR)
        lbl_img.image= spimg
        lbl_img.pack(pady=(0,10))

    ver_lbl= ttk.Label(frm, text="PrivPass (v4.2.2.1)", background=DARK_BG_COLOR, foreground=ACCENT_COLOR, font=("Helvetica",12,"bold"))
    ver_lbl.pack(pady=(0,15))

    pb= ttk.Progressbar(frm, length=300, mode='determinate')
    pb.pack(pady=10)
    pb["maximum"]=100

    def animate(step=0):
        if step>=100:
            splash.destroy()
            return
        pb["value"]= step
        splash.after(50, animate, step+2)

    animate()
    root.wait_window(splash)

# -------------------------
#   Main Manager
# -------------------------
def open_password_manager(k):
    """Clears root, builds main UI, sets global current_key. Session auto-exit after 2 min."""
    for w in root.winfo_children():
        w.destroy()

    global current_key
    current_key= k
    global last_activity_time
    last_activity_time= time.time()

    root.title("PrivPass (v4.2.2.1) — Main")
    root.config(bg=DARK_BG_COLOR)

    menu_bar= Menu(root)
    root.config(menu=menu_bar)

    file_menu= Menu(menu_bar, tearoff=0, bg=BUTTON_BG, fg=ACCENT_COLOR, font=("Helvetica",10))
    menu_bar.add_cascade(label="Options", menu=file_menu)

    file_menu.add_command(label="Make New Entry", command=add_password)
    file_menu.add_command(label="Generate Password", command=generate_password)
    file_menu.add_command(label="Search Passwords", command=search_passwords)
    file_menu.add_command(label="Delete Password", command=delete_password_topmenu)
    file_menu.add_command(label="Export Data (CSV)", command=export_data_csv)
    file_menu.add_command(label="Backup DB", command=backup_database)
    file_menu.add_separator()
    file_menu.add_command(label="Change Master Password", command=lambda: change_master_password(k))
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)

    about_menu= Menu(menu_bar, tearoff=0, bg=BUTTON_BG, fg=ACCENT_COLOR, font=("Helvetica",10))
    menu_bar.add_cascade(label="About", menu=about_menu)

    def show_about():
        msg=(
            "PrivPass (v4.2.2.1)\n\n"
            "A professional password manager for secure local storage.\n\n"
            "Features:\n"
            " • Argon2-based master password hashing\n"
            " • Cryptography (Fernet) for record encryption\n"
            " • SQLite for local data storage\n\n"
            "Pointer-based window centering for multi-monitor.\n"
            "Passwords masked by default, details auto-close in 30s.\n"
            "Auto-exit after 2 minutes of inactivity for extra security."
        )
        messagebox.showinfo("About PrivPass", msg)

    about_menu.add_command(label="About This Software", command=show_about)

    frm= ttk.Frame(root)
    frm.pack(fill="both", expand=True, padx=10, pady=10)

    global password_list
    password_list= tk.Listbox(frm, width=100, height=25, bg=DARK_LIST_BG, fg=ACCENT_COLOR, font=("Helvetica",10))
    password_list.pack(side="left", fill="both", expand=True)
    sb= tk.Scrollbar(frm)
    sb.pack(side="right", fill="y")
    password_list.config(yscrollcommand=sb.set)
    sb.config(command=password_list.yview)

    password_list.bind("<Button-3>", on_list_right_click)
    password_list.bind('<<ListboxSelect>>', on_list_select_open_details)

    update_password_list()

    root.after(30_000, check_idle_time)  # Start idle checks

AUTO_EXIT_MINUTES= 2  # Will close entire app after 2 min idle

def set_master_password():
    pw= pointer_centered_dialog(root,"Master Password Setup","Set your master password (≥12):", show='*', auto_close_seconds=60)
    if pw is None:
        return
    if len(pw)<12:
        messagebox.showerror("Error","Password must be ≥ 12 chars.")
        return
    salt= os.urandom(16).hex()
    hashed= hash_password(pw, salt)
    c.execute('INSERT INTO master_password (salt,password) VALUES(?,?)',(salt, hashed))
    conn.commit()
    messagebox.showinfo("Success","Master password set successfully!")
    open_password_manager(generate_key(pw, salt))

def verify_master_password():
    pw= pointer_centered_dialog(root,"Master Password","Enter your master password:", show='*', auto_close_seconds=60)
    if pw is None:
        return
    c.execute('SELECT salt,password FROM master_password')
    row= c.fetchone()
    if row:
        salt, hashed= row
        if verify_password(hashed, pw, salt):
            k= generate_key(pw, salt)
            open_password_manager(k)
        else:
            messagebox.showerror("Error","Incorrect master password!")
            verify_master_password()
    else:
        messagebox.showerror("Error","Master password not set!")

def change_master_password(old_key):
    old_pw= pointer_centered_dialog(root,"Change Master Password","Enter CURRENT master password:", show='*', auto_close_seconds=60)
    if old_pw is None:
        return
    c.execute('SELECT salt,password FROM master_password')
    row= c.fetchone()
    if not row:
        messagebox.showerror("Error","Master password not set!")
        return
    salt, hashed= row
    if not verify_password(hashed, old_pw, salt):
        messagebox.showerror("Error","Incorrect current master password!")
        return

    new_pw= pointer_centered_dialog(root,"Change Master Password","Enter NEW master password (≥12):", show='*', auto_close_seconds=60)
    if new_pw is None or len(new_pw)<12:
        messagebox.showerror("Error","New password must be ≥12 chars.")
        return

    new_salt= os.urandom(16).hex()
    new_hashed= hash_password(new_pw,new_salt)
    new_k= generate_key(new_pw,new_salt)
    reencrypt_database(old_key, new_k)
    c.execute('DELETE FROM master_password')
    c.execute('INSERT INTO master_password (salt,password) VALUES (?,?)',(new_salt,new_hashed))
    conn.commit()
    messagebox.showinfo("Success","Master password changed successfully!")
    open_password_manager(new_k)

# Right-click + List
def on_list_right_click(event):
    idx= password_list.nearest(event.y)
    if idx<0 or idx>= password_list.size():
        password_list.selection_clear(0,END)
        show_empty_space_menu(event)
    else:
        password_list.selection_clear(0,END)
        password_list.selection_set(idx)
        show_entry_menu(event)

def show_empty_space_menu(event):
    mm= Menu(root, tearoff=0, bg=BUTTON_BG, fg=ACCENT_COLOR, font=("Helvetica",10))
    mm.add_command(label="Make New Entry", command=add_password)
    mm.post(event.x_root, event.y_root)

def show_entry_menu(event):
    me= Menu(root, tearoff=0, bg=BUTTON_BG, fg=ACCENT_COLOR, font=("Helvetica",10))
    me.add_command(label="View/Edit Entry", command=view_selected_item)
    me.add_command(label="Delete Entry", command=delete_selected_item)
    me.add_separator()
    me.add_command(label="Make New Entry", command=add_password)
    me.post(event.x_root, event.y_root)

def on_list_select_open_details(event):
    try:
        sel= password_list.get(password_list.curselection())
        e_id= sel.split("|")[0].split(":")[1].strip()
        show_details_for_id(e_id)
    except:
        pass

def view_selected_item():
    try:
        sel= password_list.get(password_list.curselection())
        e_id= sel.split("|")[0].split(":")[1].strip()
        show_details_for_id(e_id)
    except Exception as e:
        print("Error in view_selected_item:", e)

def delete_selected_item():
    try:
        sel= password_list.get(password_list.curselection())
        e_id= sel.split("|")[0].split(":")[1].strip()
    except:
        return
    if not e_id:
        return
    cf= messagebox.askyesno("Confirm Delete", f"Delete entry ID {e_id}?")
    if cf:
        c.execute('DELETE FROM passwords WHERE id=?',(e_id,))
        conn.commit()
        update_password_list()
        messagebox.showinfo("Deleted",f"Entry {e_id} deleted successfully!")

# Add / View / Replace
def add_password():
    wsite= pointer_centered_dialog(root,"Make New Entry","Enter website:")
    if wsite is None:
        return
    wuser= pointer_centered_dialog(root,"Make New Entry","Enter username:")
    if wuser is None:
        return
    wpw= pointer_centered_dialog(root,"Make New Entry","Enter password:", show='*')
    if wpw is None:
        return
    wnts= pointer_centered_dialog(root,"Make New Entry","Enter optional notes:", show='')

    st= check_password_strength(wpw)
    if not wsite or not wuser or not wpw:
        messagebox.showwarning("Input Error","Website, username, and password are required!")
        return
    messagebox.showinfo("Password Strength", f"Your password is {st}")

    enc_u= encrypt_data(current_key, wuser)
    enc_p= encrypt_data(current_key, wpw)
    enc_n= encrypt_data(current_key, wnts) if wnts else None
    if enc_u and enc_p:
        ts= datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute('''
            INSERT INTO passwords (website,username,password,notes,modified_at)
            VALUES (?,?,?,?,?)
        ''',(wsite,enc_u,enc_p,enc_n,ts))
        conn.commit()
        messagebox.showinfo("Success","New entry added successfully!")
        update_password_list()

def show_details_for_id(e_id):
    c.execute('SELECT * FROM passwords WHERE id=?',(e_id,))
    row= c.fetchone()
    if not row:
        return
    dec_user= decrypt_data(current_key, row[2])
    dec_pass= decrypt_data(current_key, row[3])
    dec_notes= decrypt_data(current_key, row[4]) if row[4] else None
    if dec_user is None or dec_pass is None:
        return

    dwin= tk.Toplevel(root)
    dwin.title("Password Details")
    dwin.config(bg=DARK_BG_COLOR)
    # auto-close after 30s
    dwin.after(30000, dwin.destroy)

    frm2= ttk.Frame(dwin, style="TFrame")
    frm2.pack(padx=15, pady=15)

    ttk.Label(frm2, text=f"Website: {row[1]}", style="TLabel")\
        .grid(row=0, column=0, padx=5, pady=5, sticky="w")
    ttk.Button(frm2, text="Copy",
               command=lambda: copy_to_clipboard(row[1]),
               style="Accent.TButton")\
        .grid(row=0, column=1, padx=5, pady=5)
    ttk.Button(frm2, text="Replace",
               command=lambda: replace_website(e_id),
               style="Accent.TButton")\
        .grid(row=0, column=2, padx=5, pady=5)

    ttk.Label(frm2, text=f"Username: {dec_user}", style="TLabel")\
        .grid(row=1, column=0, padx=5, pady=5, sticky="w")
    ttk.Button(frm2, text="Copy",
               command=lambda: copy_to_clipboard(dec_user),
               style="Accent.TButton")\
        .grid(row=1, column=1, padx=5, pady=5)
    ttk.Button(frm2, text="Replace",
               command=lambda: replace_username(e_id),
               style="Accent.TButton")\
        .grid(row=1, column=2, padx=5, pady=5)

    masked_str= "********"
    pwd_var= tk.StringVar(value=masked_str)
    def toggle_password():
        if pwd_var.get() == masked_str:
            pwd_var.set(dec_pass)
            show_btn.config(text="Hide")
        else:
            pwd_var.set(masked_str)
            show_btn.config(text="Show")

    ttk.Label(frm2, text="Password:", style="TLabel")\
        .grid(row=2, column=0, padx=5, pady=5, sticky="e")

    pwd_lbl= ttk.Label(frm2, textvariable=pwd_var, style="TLabel")
    pwd_lbl.grid(row=2, column=1, padx=5, pady=5, sticky="w")

    show_btn= ttk.Button(frm2, text="Show", command=toggle_password, style="Accent.TButton")
    show_btn.grid(row=2, column=2, padx=5, pady=5)

    copy_btn= ttk.Button(frm2, text="Copy",
                         command=lambda: copy_to_clipboard(dec_pass),
                         style="Accent.TButton")
    copy_btn.grid(row=3, column=1, sticky="w", padx=5, pady=3)

    rep_btn= ttk.Button(frm2, text="Replace",
                        command=lambda: replace_password(e_id),
                        style="Accent.TButton")
    rep_btn.grid(row=3, column=2, padx=5, pady=3)

    s_notes= dec_notes if dec_notes else "(No notes)"
    ttk.Label(frm2, text=f"Notes: {s_notes}", style="TLabel")\
        .grid(row=4, column=0, padx=5, pady=5, sticky="w")
    ttk.Button(frm2, text="Replace",
               command=lambda: replace_notes(e_id),
               style="Accent.TButton")\
        .grid(row=4, column=2, padx=5, pady=5)

    last_up= row[5] if len(row)>5 and row[5] else "(Unknown)"
    ttk.Label(frm2, text=f"Last Updated: {last_up}", style="TLabel")\
        .grid(row=5, column=0, padx=5, pady=5, sticky="w")

    ttk.Button(frm2, text="Close", command=dwin.destroy, style="Accent.TButton")\
        .grid(row=6, column=0, columnspan=3, pady=15)

    dwin.update_idletasks()
    pointer_centered_window(root, dwin)

def update_password_list():
    password_list.delete(0,END)
    c.execute('SELECT id, website, modified_at FROM passwords')
    for row in c.fetchall():
        e_id, site, modt= row
        mod_str= f" | Last Updated: {modt}" if modt else ""
        password_list.insert(END, f"ID: {e_id} | Website: {site}{mod_str}")

def delete_password_topmenu():
    did= pointer_centered_dialog(root,"Delete Entry","Enter the ID of the entry to delete:")
    if not did or not did.isdigit():
        messagebox.showerror("Error","Please enter a valid numeric ID.")
        return
    if messagebox.askyesno("Confirm Delete", f"Delete entry ID {did}?"):
        c.execute('DELETE FROM passwords WHERE id=?',(did,))
        conn.commit()
        update_password_list()
        messagebox.showinfo("Success", f"Entry {did} deleted successfully!")

def search_passwords():
    q= pointer_centered_dialog(root,"Search Passwords","Enter website to search:")
    if q is None:
        return
    srchwin= tk.Toplevel(root)
    srchwin.title("Search Results")
    srchwin.config(bg=DARK_BG_COLOR)

    frm_s= ttk.Frame(srchwin, style="TFrame")
    frm_s.pack(padx=10, pady=10)

    s_list= tk.Listbox(frm_s, width=80, height=20, bg=DARK_LIST_BG, fg=ACCENT_COLOR, font=("Helvetica",10))
    s_list.pack(side="left", fill="both", expand=True, padx=5, pady=5)
    sc= tk.Scrollbar(frm_s)
    sc.pack(side="right", fill="y")
    s_list.config(yscrollcommand=sc.set)
    sc.config(command=s_list.yview)

    c.execute('SELECT id, website FROM passwords WHERE website LIKE ?', (f'%{q}%',))
    for row in c.fetchall():
        s_list.insert(END, f"ID: {row[0]} | Website: {row[1]}")

    srchwin.update_idletasks()
    pointer_centered_window(root, srchwin)

def export_data_csv():
    t= datetime.now().strftime("%Y%m%d_%H%M%S")
    fn= f"password_export_{t}.csv"
    c.execute('SELECT website, username, password, notes, modified_at FROM passwords')
    data= c.fetchall()
    if not data:
        messagebox.showinfo("Export Data","No data to export.")
        return
    with open(fn,"w", newline="", encoding="utf-8") as csvf:
        w= csv.writer(csvf)
        w.writerow(["Website","Username","Password","Notes","Modified At"])
        for row in data:
            site= row[0]
            dec_u= decrypt_data(current_key, row[1]) if row[1] else ""
            dec_p= decrypt_data(current_key, row[2]) if row[2] else ""
            dec_n= decrypt_data(current_key, row[3]) if row[3] else ""
            dec_m= row[4] if row[4] else ""
            w.writerow([site, dec_u, dec_p, dec_n, dec_m])
    messagebox.showinfo("Export Complete", f"Data exported to {fn} successfully!")

def on_closing():
    if messagebox.askokcancel("Exit","Are you sure you want to exit?"):
        root.quit()

root= tk.Tk()
root.title("PrivPass (v4.2.2.1)")
root.config(bg=DARK_BG_COLOR)
root.minsize(850,550)

root.withdraw()
show_splash_screen()
root.deiconify()

# pointer-based main
mw=850
mh=550
px= root.winfo_pointerx()
py= root.winfo_pointery()
mx= px-(mw//2)
my= py-(mh//2)
root.geometry(f"{mw}x{mh}+{mx}+{my}")

style= ttk.Style()
style.theme_use("clam")
style.configure("TFrame", background=DARK_BG_COLOR)
style.configure("TLabel", background=DARK_BG_COLOR, foreground=ACCENT_COLOR, font=("Helvetica",10))
style.configure("TButton", background=BUTTON_BG, foreground=BUTTON_FG, font=("Helvetica",10))
style.configure("Accent.TButton", background=BUTTON_BG, foreground=BUTTON_FG, font=("Helvetica",10))
style.configure("TEntry", fieldbackground=DARK_ENTRY_BG, foreground=ACCENT_COLOR, font=("Helvetica",10))
style.configure("TListbox", background=DARK_LIST_BG, foreground=ACCENT_COLOR, font=("Helvetica",10))
style.configure("TMenu", background=BUTTON_BG, foreground=ACCENT_COLOR, font=("Helvetica",10))
style.configure("TDialog", background=DARK_BG_COLOR, foreground=ACCENT_COLOR, font=("Helvetica",10))

last_activity_time= time.time()
AUTO_EXIT_MINUTES= 2  # Entire app closes after 2 min idle

def reset_idle_timer(event=None):
    global last_activity_time
    last_activity_time= time.time()

def check_idle_time():
    now= time.time()
    # If idle >= 2 min => close entire app
    if (now - last_activity_time)/60 >= AUTO_EXIT_MINUTES:
        # Cleanly exit the entire program
        print("Auto-exit: Inactivity limit reached.")
        root.quit()
    else:
        root.after(30000, check_idle_time)

root.protocol("WM_DELETE_WINDOW", on_closing)
root.bind_all("<Button-1>", reset_idle_timer)
root.bind_all("<KeyPress>", reset_idle_timer)

if check_master_password():
    verify_master_password()
else:
    set_master_password()

root.mainloop()
