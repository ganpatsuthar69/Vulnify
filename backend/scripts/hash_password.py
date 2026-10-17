#!/usr/bin/env python3
"""Password hashing utility for Vulnify admin accounts.

Reads a password using getpass and outputs an Argon2id hash for ADMIN_PASSWORD_HASH.
Never logs credentials or outputs raw passwords.
"""

import getpass
import sys
from argon2 import PasswordHasher


def main() -> None:
    try:
        password = getpass.getpass("Enter admin password: ")
        if not password:
            print("Error: Password cannot be empty.", file=sys.stderr)
            sys.exit(1)

        confirm = getpass.getpass("Confirm admin password: ")
        if password != confirm:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)

        ph = PasswordHasher()
        password_hash = ph.hash(password)

        print("\nGenerated Argon2id Hash:")
        print(password_hash)
        print("\nCopy this hash into your .env file:")
        print(f"ADMIN_PASSWORD_HASH='{password_hash}'")

    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
