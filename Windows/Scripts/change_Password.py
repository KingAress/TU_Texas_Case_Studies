import csv
import secrets
import ssl
import string

import requests
from ldap3 import ALL, NTLM, Connection, Server, Tls
from ldap3.extend.microsoft.modifyPassword import ad_modify_password

# AD Configurations.
AD_SERVER = "steel.texas.tu"
AD_USER = r"tx-steel\administrator"
AD_PASSWORD = "09)u0F22sBi"
SEARCH_USERBASE = "dc=tu-steel, dc=texas, DC=tu"
OUTPUT_FILE = "updated_passwords.csv"

NO_PASSWORD_CHANGE = ["administrator", "zathras", "krbtgt"]

# Nagios Configurations.
NAGIOS_URL = "https://nagios.classex.tu"
NAGIOS_USER = "texas"
NAGIOS_PASSWORD = "Y9uWdKBXk4jRxg55"


def generate_Random_Passwords(length=12):
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    while True:
        password = "".join(secrets.choice(alphabet) for i in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
        ):
            return password


tls = Tls(validate=ssl.CERT_NONE)
server = Server(AD_SERVER, use_ssl=True, tls=tls, get_info=ALL)


def ad_Password_Change(user_list):
    connection = Connection(
        server, user=AD_USER, password=AD_PASSWORD, authentication=NTLM
    )
    if not connection.bind():
        print(f"Cant connect to the AD {connection.result}")
        return False

    with open(OUTPUT_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Username", "New Password", "Status"])

        for username in user_list:
            if username.lower() in NO_PASSWORD_CHANGE:
                print(f"Skipping protected account: {username}")
                continue

            new_pw = generate_random_passwords()

            connection.search(
                search_base=SEARCH_USERBASE,
                search_filter=f"(&(objectClass=user)(sAMAccountName={username}))",
                attributes=["distinguishedName"],
            )

            if not connection.entries:
                print(f"User {username} not found in AD.")
                writer.writerow([username, "N/A", "Not Found"])
                continue

            user_dn = connection.entries[0].distinguishedName.value

            try:
                result = ad_modify_password(connection, user_dn, new_pw)
                print(f"Password change for {username}: {result}")
                writer.writerow([username, new_pw, "Success" if result else "Failed"])

                if result:
                    notify_nagios_user_change(username)

            except Exception as e:
                print(f"Error for {username}: {e}")
                writer.writerow([username, new_pw, f"Error: {e}"])

    connection.unbind()


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
        response = requests.post(
            NAGIOS_URL, data=payload, auth=(NAGIOS_USER, NAGIOS_PASSWORD), verify=False
        )
        return response.status_code
    except Exception as e:
        print(f"Nagios error: {e}")


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

    if user_list:
        print(f"Starting resets for {len(user_list)} users...")
        ad_Password_Change(user_list)


if __name__ == "__main__":
    main()
