import random
import string
import tkinter as tk
from tkinter import messagebox, Toplevel, scrolledtext, filedialog
import os
from cryptography.fernet import Fernet
import pyperclip
import hashlib
import datetime
import csv

# === Configuratie ===
KEY_FILE = "sleutel.key"
DATA_FILE = "wachtwoorden.versleuteld"
MASTER_FILE = "master.hash"

# === Kleuren ===
MODUS = {
    "dark": {"bg": "#1e1e1e", "fg": "white", "entry": "#2e2e2e", "button": "#333333"},
    "light": {"bg": "#f2f2f2", "fg": "black", "entry": "white", "button": "#dddddd"}
}
huidige_modus = "dark"

# === Versleuteling ===
def laad_sleutel():
    if not os.path.exists(KEY_FILE):
        sleutel = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(sleutel)
    else:
        with open(KEY_FILE, "rb") as f:
            sleutel = f.read()
    return Fernet(sleutel)

fernet = laad_sleutel()

# === Hoofdwachtwoordbeheer ===
def vraag_master():
    def controleer():
        invoer = entry.get()
        hashed = hashlib.sha256(invoer.encode()).hexdigest()
        if os.path.exists(MASTER_FILE):
            with open(MASTER_FILE, 'r') as f:
                opgeslagen = f.read()
            if hashed == opgeslagen:
                top.destroy()
            else:
                messagebox.showerror("Fout", "Onjuist wachtwoord.")
        else:
            with open(MASTER_FILE, 'w') as f:
                f.write(hashed)
            messagebox.showinfo("Instelling", "Hoofdwachtwoord ingesteld.")
            top.destroy()

    top = tk.Tk()
    top.title("🔐 Hoofdwachtwoord Vereist")
    top.geometry("300x150")
    tk.Label(top, text="Voer hoofdwachtwoord in:").pack(pady=10)
    entry = tk.Entry(top, show="*", width=30)
    entry.pack(pady=5)
    tk.Button(top, text="Bevestig", command=controleer).pack(pady=10)
    top.mainloop()

vraag_master()

# === Wachtwoord Logica ===
def genereer_wachtwoord(lengte):
    try:
        lengte = int(lengte)
        if lengte < 4:
            raise ValueError("Minimaal 4 tekens.")
        tekens = string.ascii_letters + string.digits
        return ''.join(random.choices(tekens, k=lengte))
    except:
        messagebox.showerror("Fout", "Voer een geldig getal in (min. 4).")
        return ""

def sla_op(beschrijving, email, wachtwoord, categorie):
    if not wachtwoord or not email:
        messagebox.showwarning("Verplicht", "E-mailadres en wachtwoord zijn verplicht.")
        return
    tijd = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    regel = f"{beschrijving} | {email} | {wachtwoord} | {categorie} | {tijd}\n"
    encrypted = fernet.encrypt(regel.encode())
    with open(DATA_FILE, "ab") as f:
        f.write(encrypted + b"\n")
    messagebox.showinfo("Opgeslagen", "Wachtwoord opgeslagen.")
    beschrijving_var.set("")
    email_var.set("")
    wachtwoord_var.set("")
    categorie_var.set("")

def kopieer_wachtwoord():
    if wachtwoord_var.get():
        pyperclip.copy(wachtwoord_var.get())
        messagebox.showinfo("Gekopieerd", "Wachtwoord gekopieerd naar klembord.")

def toggle_wachtwoord():
    if wachtwoord_entry.cget('show') == '*':
        wachtwoord_entry.config(show='')
    else:
        wachtwoord_entry.config(show='*')

def toon_opgeslagen():
    if not os.path.exists(DATA_FILE):
        messagebox.showinfo("Geen data", "Nog niets opgeslagen.")
        return
    venster = Toplevel(root)
    venster.title("🔐 Opgeslagen wachtwoorden")
    venster.geometry("600x500")
    kleuren = MODUS[huidige_modus]
    zoek_var = tk.StringVar()
    zoek_entry = tk.Entry(venster, textvariable=zoek_var, bg=kleuren["entry"], fg=kleuren["fg"], insertbackground=kleuren["fg"])
    zoek_entry.pack(pady=5, padx=10, fill='x')
    tekstveld = scrolledtext.ScrolledText(venster, wrap=tk.WORD, bg=kleuren["entry"], fg=kleuren["fg"], insertbackground=kleuren["fg"])
    tekstveld.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    with open(DATA_FILE, "rb") as f:
        decrypted_lines = []
        for regel in f:
            try:
                decrypted = fernet.decrypt(regel.strip()).decode()
                decrypted_lines.append(decrypted)
            except:
                decrypted_lines.append("[Onleesbare regel]")
    def filteren(*args):
        query = zoek_var.get().lower()
        tekstveld.delete(1.0, tk.END)
        for regel in decrypted_lines:
            if query in regel.lower():
                tekstveld.insert(tk.END, regel + "\n")
    zoek_var.trace_add("write", filteren)
    filteren()

def exporteer_bestand():
    if not os.path.exists(DATA_FILE):
        messagebox.showinfo("Geen data", "Nog niets opgeslagen.")
        return
    export_pad = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV-bestanden", "*.csv")])
    if export_pad:
        with open(DATA_FILE, "rb") as f, open(export_pad, "w", newline='', encoding="utf-8") as out:
            writer = csv.writer(out)
            writer.writerow(["Beschrijving", "E-mail", "Wachtwoord", "Categorie", "Datum"])
            for regel in f:
                try:
                    data = fernet.decrypt(regel.strip()).decode().split(" | ")
                    writer.writerow(data)
                except:
                    continue
        messagebox.showinfo("Succes", f"Geëxporteerd naar: {export_pad}")

def toggle_modus():
    global huidige_modus
    huidige_modus = "light" if huidige_modus == "dark" else "dark"
    update_styling()

def update_styling():
    kleuren = MODUS[huidige_modus]
    root.configure(bg=kleuren["bg"])
    for widget in root.winfo_children():
        cls = widget.__class__.__name__
        if cls == "Label":
            widget.configure(bg=kleuren["bg"], fg=kleuren["fg"])
        elif cls == "Entry":
            widget.configure(bg=kleuren["entry"], fg=kleuren["fg"], insertbackground=kleuren["fg"])
        elif cls == "Button":
            widget.configure(bg=kleuren["button"], fg=kleuren["fg"])

# === UI Setup ===
root = tk.Tk()
root.title("🔐 Wachtwoord Manager PRO+")
root.geometry("550x700")
root.resizable(False, False)

def label(text): return tk.Label(root, text=text)
def entry(var): return tk.Entry(root, textvariable=var, width=45)

tk.Label(root, text="Lengte wachtwoord:").pack(pady=(10, 2))
lengte_var = tk.StringVar(value="12")
lengte_entry = entry(lengte_var)
lengte_entry.pack()
tk.Button(root, text="🔁 Genereer", command=lambda: wachtwoord_var.set(genereer_wachtwoord(lengte_var.get()))).pack(pady=5)

wachtwoord_var = tk.StringVar()
tk.Label(root, text="Wachtwoord:").pack(pady=(10, 2))
wachtwoord_entry = entry(wachtwoord_var)
wachtwoord_entry.config(show='*')
wachtwoord_entry.pack()
tk.Button(root, text="👁 Toggle zichtbaarheid", command=toggle_wachtwoord).pack(pady=5)
tk.Button(root, text="📋 Kopieer wachtwoord", command=kopieer_wachtwoord).pack(pady=5)

tk.Label(root, text="E-mailadres:").pack(pady=(10, 2))
email_var = tk.StringVar()
entry(email_var).pack()

tk.Label(root, text="Beschrijving:").pack(pady=(10, 2))
beschrijving_var = tk.StringVar()
entry(beschrijving_var).pack()

tk.Label(root, text="Categorie:").pack(pady=(10, 2))
categorie_var = tk.StringVar()
entry(categorie_var).pack()

tk.Button(root, text="💾 Sla op", command=lambda: sla_op(beschrijving_var.get(), email_var.get(), wachtwoord_var.get(), categorie_var.get())).pack(pady=10)
tk.Button(root, text="📜 Toon wachtwoorden", command=toon_opgeslagen).pack(pady=5)
tk.Button(root, text="📁 Exporteer naar CSV", command=exporteer_bestand).pack(pady=5)
tk.Button(root, text="🌓 Wissel modus", command=toggle_modus).pack(pady=10)

update_styling()
root.mainloop()