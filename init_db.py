import sqlite3

# create DB file
con = sqlite3.connect("accounts.db")

# create accounts table
con.execute("""
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    app_password TEXT
)
""")

con.commit()
con.close()

print("✅ Database ready: accounts.db created")
