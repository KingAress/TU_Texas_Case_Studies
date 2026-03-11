import subprocess
import requests
import secrets
import string
import csv
import time

AD_SERVER = "irving.steel.texas.tu"
AD_USER = "administrator@steel.texas.tu"
AD_PASSWORD = "09)u0F22sBi"
BASE_DN = "dc=steel,dc=texas,dc=tu"

LOGIN_URL = "http://webapps.classex.tu/webpass/"
PASSWORD_PAGE = "http://webapps.classex.tu/webpass/index.php"

TEAM_NAME = "texas"
TEAM_PASSWORD = "pleaseStopT@kingMyMoney"

OUTPUT_FILE = "rotated_passwords.csv"

NO_PASSWORD_CHANGE = [
    "administrator",
    "zathras",
    "krbtgt",
    "tre-admin",
    "simon-admin",
    "hudson-admin",
    "brian-admin",
    "TexasAdmin",
    "Tx-steel\\administrator"
]


def generate_base_password(length=12):

    letters = string.ascii_letters
    numbers = string.digits
    symbols = "!@#$^*_-"

    alphabet = letters + numbers + symbols

    return "".join(secrets.choice(alphabet) for _ in range(length))


def get_users_from_ad():

    cmd = [
        "ldapsearch",
        "-x",
        "-H", f"ldap://{AD_SERVER}",
        "-D", AD_USER,
        "-w", AD_PASSWORD,
        "-b", BASE_DN,
        "(objectCategory=person)",
        "sAMAccountName"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    users = []

    for line in result.stdout.splitlines():

        if line.startswith("sAMAccountName:"):

            username = line.split(":")[1].strip()

            if username.endswith("$"):
                continue

            if username.lower() in [u.lower() for u in NO_PASSWORD_CHANGE]:
                continue

            users.append(username)

    users = list(set(users))

    return users


def login_texas(session):

    payload = {
        "team": TEAM_NAME,
        "password": TEAM_PASSWORD
    }

    session.post(LOGIN_URL, data=payload)


def verify_password_page(session):

    session.get(PASSWORD_PAGE)


def rotate_passwords(session, users):

    with open(OUTPUT_FILE, "w", newline="") as file:

        writer = csv.writer(file)
        writer.writerow(["username", "base_password"])

        for index, username in enumerate(users, 1):

            base_password = generate_base_password()

            payload = {
                "user": username,
                "password1": base_password,
                "password2": base_password
            }

            r = session.post(PASSWORD_PAGE, data=payload)

            if r.status_code == 200:
                print(f"[{index}/{len(users)}] Updated:", username)
                writer.writerow([username, base_password])

            time.sleep(0.2)


def main():

    users = get_users_from_ad()

    session = requests.Session()

    login_texas(session)

    verify_password_page(session)

    rotate_passwords(session, users)


if __name__ == "__main__":
    main()
