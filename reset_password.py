"""Usage: python reset_password.py [username] [new_password]   (DATABASE_URL must be set)"""
import getpass
import sys

from app.core.security import hash_password
from app.database.database import SessionLocal
from app.models.user import User

username = sys.argv[1] if len(sys.argv) > 1 else input("Username: ")
new_password = sys.argv[2] if len(sys.argv) > 2 else getpass.getpass("New password (12+ chars): ")

if len(new_password) < 12:
    sys.exit("Password must be at least 12 characters.")

db = SessionLocal()
user = db.query(User).filter(User.username == username).first()
if user is None:
    db.close()
    sys.exit(f"No user named {username}")

user.password_hash = hash_password(new_password)
db.commit()
print(f"Password updated for {username} (id={user.id})")
db.close()
