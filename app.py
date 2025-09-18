from flask import Flask, render_template, request, redirect, url_for
import sqlite3, imaplib, email
from email.header import decode_header
from datetime import datetime, timedelta

app = Flask(__name__)
DB_FILE = "accounts.db"
IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993

# --- DB Helper ---
def get_accounts():
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("SELECT id, email, app_password FROM accounts")
    rows = cur.fetchall()
    con.close()
    return rows

# --- Mail Helpers ---
def clean_subject(raw_subj):
    if not raw_subj:
        return ""
    parts = decode_header(raw_subj)
    result = []
    for subj, enc in parts:
        if isinstance(subj, bytes):
            try:
                result.append(subj.decode(enc or "utf-8", errors="ignore"))
            except:
                result.append(subj.decode(errors="ignore"))
        else:
            result.append(str(subj))
    return "".join(result).strip()

def fetch_last_subjects(email_user, email_pass, days=1, limit=5):
    results = {"INBOX": [], "SPAM": [], "PROMOTIONS": [], "UPDATES": []}
    folders = {
        "INBOX": "INBOX",
        "SPAM": "[Gmail]/Spam",
        "PROMOTIONS": "[Gmail]/Promotions",
        "UPDATES": "[Gmail]/Updates"
    }
    try:
        with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT) as imap:
            imap.login(email_user, email_pass)
            for name, path in folders.items():
                try:
                    imap.select(path, readonly=True)
                    date_since = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")
                    status, data = imap.search(None, f'(SINCE {date_since})')
                    if status == "OK" and data[0]:
                        ids = data[0].split()[-limit:]
                        for msg_id in ids:
                            res, msg_data = imap.fetch(msg_id, "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
                            if res == "OK" and msg_data and msg_data[0]:
                                msg = email.message_from_bytes(msg_data[0][1])
                                results[name].append(clean_subject(msg.get("Subject")))
                except:
                    results[name].append("<error>")
            imap.logout()
    except Exception as e:
        return {"error": str(e)}
    return results

# --- Routes ---
@app.route("/")
def index():
    accounts = get_accounts()
    return render_template("index.html", accounts=accounts)

@app.route("/check/<int:acc_id>")
def check(acc_id):
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("SELECT email, app_password FROM accounts WHERE id=?", (acc_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return "Account not found", 404
    results = fetch_last_subjects(row[0], row[1])
    return render_template("results.html", email=row[0], results=results)

if __name__ == "__main__":
    app.run(debug=True)
