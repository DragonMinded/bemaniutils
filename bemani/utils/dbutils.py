import argparse
import getpass
import sys
from typing import Optional

from bemani.data import Config, Data, DBCreateException
from bemani.utils.config import load_config


def create(config: Config) -> None:
    data = Data(config)
    data.create()
    data.close()


def generate(config: Config, message: Optional[str], allow_empty: bool) -> None:
    if message is None:
        raise Exception("Please provide a message!")
    data = Data(config)
    data.generate(message, allow_empty)
    data.close()


def upgrade(config: Config) -> None:
    data = Data(config)
    data.upgrade()
    data.close()


def change_password(config: Config, username: Optional[str]) -> None:
    if username is None:
        raise Exception("Please provide a username!")
    password1 = getpass.getpass("Password: ")
    password2 = getpass.getpass("Re-enter password: ")
    if password1 != password2:
        raise Exception("Passwords don't match!")
    data = Data(config)
    userid = data.local.user.from_username(username)
    if userid is None:
        raise Exception("User not found!")
    data.local.user.update_password(userid, password1)
    print(f"User {username} changed password.")


def add_admin(config: Config, username: Optional[str]) -> None:
    if username is None:
        raise Exception("Please provide a username!")
    data = Data(config)
    userid = data.local.user.from_username(username)
    if userid is None:
        raise Exception("User not found!")
    user = data.local.user.get_user(userid)
    user.admin = True
    data.local.user.put_user(user)
    print(f"User {username} gained admin rights.")


def remove_admin(config: Config, username: Optional[str]) -> None:
    if username is None:
        raise Exception("Please provide a username!")
    data = Data(config)
    userid = data.local.user.from_username(username)
    if userid is None:
        raise Exception("User not found!")
    user = data.local.user.get_user(userid)
    user.admin = False
    data.local.user.put_user(user)
    print(f"User {username} lost admin rights.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A utility for working with databases created with this codebase."
    )
    parser.add_argument(
        "operation",
        help="Operation to perform, options include 'create', 'generate', 'upgrade', 'change-password', 'add-admin' and 'remove-admin'.",
        type=str,
    )
    parser.add_argument(
        "-u",
        "--username",
        help="Username of user to add/remove admin rights for.",
        type=str,
    )
    parser.add_argument(
        "-m",
        "--message",
        help="Message to use for auto-generated migration scripts.",
        type=str,
    )
    parser.add_argument(
        "-e",
        "--allow-empty",
        help="Allow empty migration script to be generated. Useful for data-only migrations.",
        action="store_true",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Core configuration. Defaults to server.yaml",
        type=str,
        default="server.yaml",
    )
    args = parser.parse_args()

    config = Config()
    load_config(args.config, config)

    try:
        if args.operation == "create":
            create(config)
        elif args.operation == "generate":
            generate(config, args.message, args.allow_empty)
        elif args.operation == "upgrade":
            upgrade(config)
        elif args.operation == "add-admin":
            add_admin(config, args.username)
        elif args.operation == "remove-admin":
            remove_admin(config, args.username)
        elif args.operation == "change-password":
            change_password(config, args.username)
        else:
            raise Exception(f"Unknown operation '{args.operation}'")
    except DBCreateException as e:
        print(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
