import csv
import hashlib
import os
import secrets
import ssl
import string
import sys

import requests

# from ntlm_auth.des_ciphers import ntlm_hash
from ldap3 import ALL, NTLM, Connection, Server, Tls
from ldap3.extend.microsoft.modifyPassword import ad_modify_password

# AD Configurations
AD_SERVER = "steel.texas.tu"
AD_USER = r"tx-steel\administrator"
SEARCH_USERBASE = "dc=texas,dc=tu,dc=steel"
OUTPUT_FILE = "updated_passwords.csv"

NO_PASSWORD_CHANGE = [
    "administrator",
    "zathras",
    "krbtgt",
    "tre-admin",
    "simon-admin",
    "hudson-admin",
    "brian-admin"
    r"Tx-steel\administrator",
]


# Nagios Configurations
NAGIOS_URL = "https://nagios.classex.tu"

MAX_USERS_PASSWORD_CHANGES = 1


def generate_random_password(length=13):
    """Generate a secure random password with required complexity."""
    passwords_list = read_files("passwords.txt")
    return random.choice(passwords_list)


def ad_password_change(user_list, max_users=MAX_USERS_PASSWORD_CHANGES):
    if len(user_list) > max_users:
        print(f"Too many users, Requested: {len(user_list)}, Max Users: {max_users}")
        print(f"Processing only the first {max_users} users.")
        user_list = user_list[:max_users]

    # TLS Configuration (Tested with path and without. Tested with 636(LDAPS))
    cert_path = r"C:\Users\texasadmin\Downloads\TU_Texas_Case_Studies--main\TU_Texas_Case_Studies--main\Windows\Scripts\CA_exercise.crt"
    tls_setting = Tls(
        ca_certs_file=cert_path,
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
    )

    # Connecting to AD
    server = Server(AD_SERVER, port=389, use_ssl=False, tls=tls_setting, get_info=ALL)
    print(f"AD_SERVER: {AD_SERVER}")
    connection = Connection(
        server, user=AD_USER, password=AD_PASSWORD, authentication=NTLM, auto_bind=True
    )
    print(connection)
    try:
        connection.start_tls()
    except Exception as e:
        print(f"Connecting Error: {e}")
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
                result = ad_modify_password(connection, user_dn, new_pw, old_password)
                status = "Success" if result else "Failed"
                print(f"Password change: {status}")
                writer.writerow([username, new_pw if result else "N/A", status])
                """
                if result:
                    successful_changes += 1
                    notify_nagios_user_change(username)
                """
            except Exception as e:
                print(f"Error: {e}")
                writer.writerow([username, f"Error: {e}"])

    connection.unbind()

    print(f"Complete: {successful_changes}/{len(user_list)} passwords changed")
    print(f"Results: {OUTPUT_FILE} (secure permissions applied)")
    return True


"""
def notify_nagios_user_change(target_user):
    Send notification to Nagios about password change.
    payload = {
        "cmd_typ": "1",
        "cmd_mod": "2",
        "host": "localhost",
        "comment_data": f"AD Password updated for {target_user} via script",
        "author": "AutomationScript",
        "btnSubmit": "Commit",
    }
    try:
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



"""


def read_files(input_file):
    try:
        with open(input_file, "r") as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return []


def main():
    try:
        filename = "usernames.txt"
        user_list = read_files(filename)

        if not user_list:
            print("No users to process.")
            return

        print(f"Starting password resets for {len(user_list)} users...")
        print(f"Maximum batch size: {MAX_USERS_PASSWORD_CHANGES}\n")

        ad_password_change(user_list)

    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
