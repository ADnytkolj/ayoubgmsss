import imaplib
import email
from email.header import decode_header
from datetime import datetime, timedelta
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993
DB_FILE = "accounts.db"   # 🔹 our SQLite database

# === Helpers ===
def load_accounts_from_db():
    """Fetch all accounts from SQLite DB"""
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("SELECT email, app_password FROM accounts")
    rows = cur.fetchall()
    con.close()
    return rows

def clean_subject(raw_subj):
    if not raw_subj:
        return ""
    parts = decode_header(raw_subj)
    segments = []
    for subj, enc in parts:
        if isinstance(subj, bytes):
            try:
                segments.append(subj.decode(enc or "utf-8", errors="ignore"))
            except:
                segments.append(subj.decode(errors="ignore"))
        else:
            segments.append(str(subj))
    return "".join(segments).strip()

def fetch_last_subjects(imap, folder, limit=10, days=1):
    subjects = []
    try:
        status, _ = imap.select(folder, readonly=True)
        if status != "OK":
            return ["<empty>"]

        date_since = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")
        status, data = imap.search(None, f'(SINCE {date_since})')
        if status != "OK" or not data or not data[0]:
            return ["<empty>"]

        ids = data[0].split()
        last_ids = ids[-limit:]
        for i in reversed(last_ids):
            res, msg_data = imap.fetch(i, "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
            if res != "OK" or not msg_data or not msg_data[0]:
                continue
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)
            subj = clean_subject(msg.get("Subject"))
            subjects.append(subj if subj else "<no subject>")

        return subjects if subjects else ["<empty>"]
    except:
        return ["<empty>"]

def worker_check_accounts(accounts_to_check, days, result_queue, stop_event):
    folders = {
        "SPAM": "[Gmail]/Spam",
        "INBOX": "INBOX",
        "PROMOTIONS": "[Gmail]/Promotions",
        "UPDATES": "[Gmail]/Updates"
    }
    for email_user, email_pass in accounts_to_check:
        if stop_event.is_set():
            break
        try:
            with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT) as imap:
                imap.login(email_user, email_pass)
                results = {name: fetch_last_subjects(imap, path, 10, days)
                           for name, path in folders.items()}
                imap.logout()
                result_queue.put(("ok", email_user, results))
        except Exception as e:
            result_queue.put(("error", email_user, f"Login error: {e}"))

# === GUI ===
class IMAPCheckerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IMAP Boîtes Checker")
        self.geometry("950x600")

        # 🔹 Load accounts from DB
        self.accounts = load_accounts_from_db()

        self.result_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker_thread = None

        self.create_widgets()
        self.load_accounts()
        self.after(300, self.process_queue)

    def create_widgets(self):
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=8, pady=6)

        ttk.Label(top_frame, text="Days to scan:").pack(side="left")
        self.days_var = tk.IntVar(value=1)
        ttk.Spinbox(top_frame, from_=0, to=30, width=4,
                    textvariable=self.days_var).pack(side="left")

        left_frame = ttk.Frame(self)
        left_frame.pack(side="left", fill="y", padx=8, pady=6)

        ttk.Label(left_frame, text="Select boîtes:").pack(anchor="w")
        self.lb = tk.Listbox(left_frame, selectmode="extended", width=40, height=25)
        self.lb.pack(side="left", fill="y")
        sb = ttk.Scrollbar(left_frame, command=self.lb.yview)
        sb.pack(side="left", fill="y")
        self.lb.config(yscrollcommand=sb.set)

        btns = ttk.Frame(left_frame)
        btns.pack(fill="x", pady=8)
        ttk.Button(btns, text="Check Selected", command=self.check_selected).pack(fill="x", pady=2)
        ttk.Button(btns, text="Check All", command=self.check_all).pack(fill="x", pady=2)
        ttk.Button(btns, text="Stop", command=self.stop_worker).pack(fill="x", pady=2)

        right_frame = ttk.Frame(self)
        right_frame.pack(side="left", fill="both", expand=True, padx=6, pady=6)

        self.nb = ttk.Notebook(right_frame)
        self.nb.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="Idle")
        status = ttk.Label(self, textvariable=self.status_var,
                           relief="sunken", anchor="w")
        status.pack(fill="x", side="bottom")

    def load_accounts(self):
        self.lb.delete(0, tk.END)
        for email_user, _ in self.accounts:
            self.lb.insert(tk.END, email_user)
        self.status_var.set(f"Loaded {len(self.accounts)} boîtes from DB")

    def check_selected(self):
        sel = self.lb.curselection()
        if not sel:
            messagebox.showinfo("Info", "Select at least one boîte")
            return
        to_check = [self.accounts[i] for i in sel]
        self.start_worker(to_check)

    def check_all(self):
        self.start_worker(self.accounts)

    def start_worker(self, accounts_to_check):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("Busy", "Already checking")
            return
        for tab in self.nb.tabs():
            self.nb.forget(tab)
        self.stop_event.clear()
        self.result_queue = queue.Queue()
        days = int(self.days_var.get())
        self.worker_thread = threading.Thread(
            target=worker_check_accounts,
            args=(accounts_to_check, days, self.result_queue, self.stop_event),
            daemon=True
        )
        self.worker_thread.start()
        self.status_var.set(f"Checking {len(accounts_to_check)} boîtes...")

    def stop_worker(self):
        self.stop_event.set()
        self.status_var.set("Stopping...")

    def process_queue(self):
        try:
            while True:
                item = self.result_queue.get_nowait()
                tag = item[0]
                if tag == "ok":
                    email_user, results = item[1], item[2]
                    self.display_results(email_user, results)
                else:
                    email_user, msg = item[1], item[2]
                    self.display_error(email_user, msg)
        except queue.Empty:
            pass
        self.after(300, self.process_queue)

    def display_results(self, email_user, results):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text=email_user)

        cols = ("SPAM", "INBOX", "PROMOTIONS", "UPDATES")
        tv = ttk.Treeview(frame, columns=cols, show="headings")
        for c in cols:
            tv.heading(c, text=c)
            tv.column(c, width=200, anchor="w")
        tv.pack(fill="both", expand=True, padx=4, pady=4)

        max_len = max(len(results[c]) for c in cols)
        for i in range(max_len):
            row = [results[c][i] if i < len(results[c]) else "" for c in cols]
            tv.insert("", "end", values=row)

    def display_error(self, email_user, msg):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text=f"{email_user} (error)")
        ttk.Label(frame, text=f"{msg}", foreground="red").pack(padx=8, pady=8)

if __name__ == "__main__":
    app = IMAPCheckerGUI()
    app.mainloop()
