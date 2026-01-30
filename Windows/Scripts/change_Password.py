import csv
import os
import secrets
import ssl
import string

import requests
from ldap3 import ALL, NTLM, Connection, Server, Tls
from ldap3.extend.microsoft.modifyPassword import ad_modify_password

# AD Configurations
AD_SERVER = "steel.texas.tu"
AD_USER = r"tx-steel\administrator"
AD_PASSWORD = os.getenv("AD_PASSWORD", "09)u0F22sBi")
SEARCH_USERBASE = "dc=texas,dc=tu"
OUTPUT_FILE = "updated_passwords.csv"
NO_PASSWORD_CHANGE = ["administrator", "zathras", "krbtgt"]

# Nagios Configurations
NAGIOS_URL = "https://nagios.classex.tu"
NAGIOS_USER = os.getenv("NAGIOS_USER", "texas")
NAGIOS_PASSWORD = os.getenv("NAGIOS_PASSWORD", "Y9uWdKBXk4jRxg55")

MAX_USERS_PASSWORD_CHANGES = 10


def generate_random_password(length=13):
    """Generate a secure random password with required complexity."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()_+-=" for c in password)
        ):
            return password


# enable SSL in production
tls = Tls(validate=ssl.CERT_NONE)
server = Server(AD_SERVER, use_ssl=True, tls=tls, get_info=ALL)


def ad_password_change(user_list, max_users=MAX_USERS_PASSWORD_CHANGES):
    if len(user_list) > max_users:
        print(f"Too many users, Requested: {len(user_list)}, Max Users: {max_users}")
        print(f"Processing only the first {max_users} users.")
        user_list = user_list[:max_users]

    connection = Connection(
        server, user=AD_USER, password=AD_PASSWORD, authentication=NTLM
    )

    if not connection.bind():
        print(f"Cannot connect to AD: {connection.result}")
        return False

    successful_changes = 0

    with open(OUTPUT_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Username", "New Password", "Status"])

        for index, username in enumerate(user_list, 1):
            print(f"\n[{index}/{len(user_list)}] Processing: {username}")

            if username.lower() in NO_PASSWORD_CHANGE:
                print("Skipping protected account")
                writer.writerow([username, "Protected"])
                continue

            new_pw = generate_random_password()
            connection.search(
                search_base=SEARCH_USERBASE,
                search_filter=f"(&(objectClass=user)(sAMAccountName={username}))",
                attributes=["distinguishedName"],
            )

            if not connection.entries:
                print("User not found in AD")
                writer.writerow([username, "Not Found"])
                continue

            user_dn = connection.entries[0].distinguishedName.value

            try:
                result = ad_modify_password(connection, user_dn, new_pw)
                status = "Success" if result else "Failed"
                print(f"  → Password change: {status}")

                writer.writerow([username, new_pw if result else "N/A", status])

                if result:
                    successful_changes += 1
                    notify_nagios_user_change(username)
            except Exception as e:
                print(f"  → Error: {e}")
                writer.writerow([username, "N/A", f"Error: {e}"])

    connection.unbind()

    os.chmod(OUTPUT_FILE, 0o600)
    print(f" Complete: {successful_changes}/{len(user_list)} passwords changed")
    print(f"Results: {OUTPUT_FILE} (secure permissions applied)")
    return True


def notify_nagios_user_change(target_user):
    payload = {
        "cmd_typ": "1",
        "cmd_mod": "2",
        "host": "localhost",
        "comment_data": f"AD Password updated for {target_user} via script",
        "author": "AutomationScript",
        "btnSubmit": "Commit",
    }

    try:
        # SSL verification disabled enable in production
        response = requests.post(
            NAGIOS_URL,
            data=payload,
            auth=(NAGIOS_USER, NAGIOS_PASSWORD),
            verify=False,
            timeout=10,
        )
        if response.status_code == 200:
            print("Nagios notified")
        return response.status_code
    except Exception as e:
        print(f"Nagios error: {e}")
        return None


def read_files(input_file):
    try:
        with open(input_file, "r") as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return []


def main():
    filename = "usernames.txt"
    user_list = read_files(filename)

    if not user_list:
        print("No users to process.")
        return

    print(f"Starting password resets for {len(user_list)} users...")
    print(f"Maximum batch size: {MAX_USERS_PASSWORD_CHANGES}\n")

    ad_password_change(user_list)


if __name__ == "__main__":
    main()
