"""Create shielddesk.db and fill it with SYNTHETIC data only (Faker).
Usage:  python3 seed.py md5      (for v0 - weak hashes)
        python3 seed.py secure   (for v1 - salted KDF hashes)
"""
import hashlib
import random
import sqlite3
import sys
 
from faker import Faker
from werkzeug.security import generate_password_hash
 
MODE = sys.argv[1] if len(sys.argv) > 1 else "md5"
fake = Faker()
Faker.seed(401)
random.seed(401)
 
 
def hpw(pw):
    if MODE == "md5":
        return hashlib.md5(pw.encode()).hexdigest()
    return generate_password_hash(pw)          # scrypt/pbkdf2 with random salt
 
 
db = sqlite3.connect("shielddesk.db")
with open("schema.sql") as f:
    db.executescript(f.read())
 
# Fixed demo accounts (fake)
db.execute("INSERT INTO users (username,password,full_name,student_id,email,role) VALUES (?,?,?,?,?,?)",
           ("admin", hpw("Admin#Pass2026"), "Desk Admin", "00000000", "admin@shielddesk.test", "admin"))
db.execute("INSERT INTO users (username,password,full_name,student_id,email,role) VALUES (?,?,?,?,?,?)",
           ("alice", hpw("Summer2026!"), "Alice Test", "20230001", "alice@shielddesk.test", "user"))
db.execute("INSERT INTO users (username,password,full_name,student_id,email,role) VALUES (?,?,?,?,?,?)",
           ("bob", hpw("Summer2026!"), "Bob Test", "20230002", "bob@shielddesk.test", "user"))
 
categories = ["IT", "Finance", "Housing", "Registration", "Library"]
for i in range(40):
    uname = f"stu{i:03d}"
    db.execute("INSERT INTO users (username,password,full_name,student_id,email,role) VALUES (?,?,?,?,?,?)",
               (uname, hpw(fake.password(length=12)), fake.name(),
                f"2023{random.randint(1000, 9999)}", f"{uname}@shielddesk.test", "user"))
    for _ in range(random.randint(1, 3)):
        db.execute("INSERT INTO requests (username,category,details,status,created_at) VALUES (?,?,?,?,?)",
                   (uname, random.choice(categories), fake.sentence(nb_words=10),
                    random.choice(["Open", "In progress", "Closed"]),
                    fake.date_time_between(start_date="-180d").isoformat(sep=" ", timespec="seconds")))
db.commit()
print("Seeded", db.execute("SELECT COUNT(*) FROM users").fetchone()[0], "users and",
      db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], "requests (all synthetic).")
