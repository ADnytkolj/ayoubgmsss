import sqlite3
import tkinter as tk
from tkinter import scrolledtext, messagebox

DB_FILE = "accounts.db"
INPUT_FILE = "accounts.txt"

def add_accounts_from_file(output_box):
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()
    except Exception as e:
        messagebox.showerror("DB Error", str(e))
        return

    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        messagebox.showerror("File Error", f"{INPUT_FILE} not found")
        return

    added, skipped = 0, 0
    for line in lines:
        line = line.strip()
        if not line or ":" not in line:
            continue
        email, app_pass = line.split(":", 1)
        try:
            cur.execute("INSERT INTO accounts (email, app_password) VALUES (?, ?)", (email.strip(), app_pass.strip()))
            output_box.insert(tk.END, f"✅ Added: {email}\n")
            added += 1
        except sqlite3.IntegrityError:
            output_box.insert(tk.END, f"⚠️ Already exists: {email}\n")
            skipped += 1
        except Exception as e:
            output_box.insert(tk.END, f"❌ Error {email}: {e}\n")

    con.commit()
    con.close()
    output_box.insert(tk.END, f"\n🎉 Done! {added} added, {skipped} skipped.\n")
    output_box.see(tk.END)

def run_gui():
    root = tk.Tk()
    root.title("Add Accounts to DB")
    root.geometry("600x400")

    tk.Label(root, text=f"Reading from: {INPUT_FILE}", font=("Arial", 11, "bold")).pack(pady=5)

    output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=15)
    output_box.pack(padx=10, pady=10, fill="both", expand=True)

    btn = tk.Button(root, text="Add Accounts", command=lambda: add_accounts_from_file(output_box))
    btn.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    run_gui()
