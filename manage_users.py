"""Manage PQConnect accounts. There is no public sign-up.

  python manage_users.py add <username>      prompts for a password (min 12 chars)
  python manage_users.py remove <username>
  python manage_users.py list
"""
import getpass
import json
import re
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

USERS = Path(__file__).resolve().parent / "instance" / "users.json"


def load():
    return json.loads(USERS.read_text()) if USERS.exists() else {}


def save(users):
    USERS.parent.mkdir(exist_ok=True)
    USERS.write_text(json.dumps(users, indent=2))
    USERS.chmod(0o600)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("add", "remove", "list"):
        sys.exit(__doc__)
    users = load()
    cmd = sys.argv[1]
    if cmd == "list":
        print("\n".join(sorted(users)) or "(no accounts)")
        return
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    name = sys.argv[2]
    if cmd == "remove":
        if users.pop(name, None) is None:
            sys.exit(f"No account called {name}.")
        save(users)
        print(f"Removed {name}.")
        return
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", name):
        sys.exit("Username: 3 to 64 letters, digits, dot, dash or underscore.")
    pw = getpass.getpass("Password: ")
    if len(pw) < 12:
        sys.exit("Password must be at least 12 characters.")
    if pw != getpass.getpass("Repeat password: "):
        sys.exit("Passwords did not match.")
    users[name] = generate_password_hash(pw)
    save(users)
    print(f"Saved account {name}.")


if __name__ == "__main__":
    main()
