#!/usr/bin/env python3
"""Deliberate administrative provisioning script for Vulnify.

Allows operators to promote an existing registered user to the 'admin' role in FalkorDB.
Never hardcodes default credentials or logs secrets.
"""

import argparse
import sys
from vulnify.config import get_settings
from vulnify.graph.client import GraphClient
from vulnify.graph.user_repository import FalkorUserRepository


def main() -> None:
    parser = argparse.ArgumentParser(description="Promote a user to admin or update user role.")
    parser.add_argument("email", help="Email of the registered user to promote")
    parser.add_argument(
        "--role",
        choices=["admin", "user"],
        default="admin",
        help="Target role (default: admin)",
    )
    args = parser.parse_args()

    email = args.email.strip().lower()
    target_role = args.role

    try:
        settings = get_settings()
        client = GraphClient(settings)
        repo = FalkorUserRepository(client)

        user = repo.get_by_email(email)
        if not user:
            print(f"Error: No registered user found with email '{email}'.", file=sys.stderr)
            sys.exit(1)

        updated = repo.update_role(email, target_role)
        if not updated:
            print(f"Error: Failed to update role for '{email}'.", file=sys.stderr)
            sys.exit(1)

        print(f"Success: User '{email}' ({user.name}) has been assigned role '{target_role}'.")

    except Exception as e:
        print(f"Error executing role update: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
