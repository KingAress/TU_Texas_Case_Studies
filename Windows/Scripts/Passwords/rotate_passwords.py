import argparse
import csv
import os
import random
import ssl
import sys
import time

import requests
from bs4 import BeautifulSoup
from ldap3 import ALL, NTLM, Connection, Server, Tls
from ldap3.extend.microsoft.modifyPassword import ad_modify_password

NETWORK_CONFIG = {
    "steel":  {"ad_server": "steel.texas.tu",  "base_dn": "dc=steel,dc=texas,dc=tu",  "prefix": "3eJ"},
    "mining": {"ad_server": "mining.texas.tu", "base_dn": "dc=mining,dc=texas,dc=tu", "prefix": "fq*"},
    "aero":   {"ad_server": "aero.texas.tu",   "base_dn": "dc=aero,dc=texas,dc=tu",   "prefix": "E2L"},
    "auto":   {"ad_server": "auto.texas.tu",   "base_dn": "dc=auto,dc=texas,dc=tu",   "prefix": "qR#"},
    "chem":   {"ad_server": "chem.texas.tu",   "base_dn": "dc=chem,dc=texas,dc=tu",   "prefix": "5M0"},
}

WEBPASS_LOGIN_URL = "http://webapps.classex.tu/webpass/"
PASSWORD_PAGE     = "http://webapps.classex.tu/webpass/index.php"

TEAM_NAME     = os.getenv("TEAM_NAME",     "texas")
TEAM_PASSWORD = os.getenv("TEAM_PASSWORD", "pleaseStopT@kingMyMoney")

AD_ADMIN_PASSWORD = os.getenv("AD_PASSWORD", "09)u0F22sBi")

CERT_PATH = os.getenv(
    "AD_CERT_PATH",
    r"C:\Users\texasadmin\Downloads\TU_Texas_Case_Studies--main"
    r"\TU_Texas_Case_Studies--main\Windows\Scripts\CA_exercise.crt",
)

NO_PASSWORD_CHANGE = {
    "administrator",
    "zathras",
    "krbtgt",
    "tre-admin",
    "simon-admin",
    "hudson-admin",
    "brian-admin",
    "TexasAdmin",
}

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
USERS_FILE    = os.path.join(SCRIPT_DIR, "Users", "users.txt")
PASSWORD_FILE = os.path.join(SCRIPT_DIR, "passwords.txt")


def read_lines(filepath: str) -> list[str]:
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)


def nagios_session() -> requests.Session:
    """Log in to the webpass portal and return an authenticated session."""
    session = requests.Session()
    session.verify = False  # internal lab environment; no public CA
    try:
        resp = session.post(
            WEBPASS_LOGIN_URL,
            data={"team": TEAM_NAME, "password": TEAM_PASSWORD},
            timeout=15,
        )
        if resp.status_code != 200:
            print(f"[WARN] Webpass login returned HTTP {resp.status_code}")
    except requests.RequestException as exc:
        print(f"[ERROR] Could not reach webpass login page: {exc}")
        sys.exit(1)

    print("[INFO] Logged in to webpass portal.")
    return session


def change_nagios_password(session: requests.Session, username: str, base_pw: str) -> str:
    """
    Change a user's Nagios/webpass password to *base_pw* (no network prefix).

    Returns a short status string: 'Success', 'HTTP <code>', or an error message.
    """
    try:
        page = session.get(PASSWORD_PAGE, timeout=15)
        soup = BeautifulSoup(page.text, "html.parser")

        # Collect every named input field so we preserve any hidden tokens
        form_data: dict[str, str] = {}
        for inp in soup.find_all("input"):
            name = inp.get("name")
            if name:
                form_data[name] = inp.get("value", "")

        # Overwrite the fields that matter
        form_data["user"]      = username
        form_data["password1"] = base_pw
        form_data["password2"] = base_pw

        resp = session.post(PASSWORD_PAGE, data=form_data, timeout=15)
        if resp.status_code == 200:
            return "Success"
        return f"HTTP {resp.status_code}"

    except requests.RequestException as exc:
        return f"Error: {exc}"



def ad_connection(network: str) -> tuple[Connection, str]:
    """
    Open an authenticated LDAP(S) connection to the network's AD server.

    Returns (connection, base_dn).
    """
    cfg        = NETWORK_CONFIG[network]
    ad_server  = cfg["ad_server"]
    base_dn    = cfg["base_dn"]
    ad_user    = rf"tx-{network}\administrator"

    tls_config = Tls(
        ca_certs_file=CERT_PATH,
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
    )

    server = Server(ad_server, port=389, use_ssl=False, tls=tls_config, get_info=ALL)
    conn   = Connection(
        server,
        user=ad_user,
        password=AD_ADMIN_PASSWORD,
        authentication=NTLM,
        auto_bind=True,
    )

    try:
        conn.start_tls()
        print(f"[INFO] Connected to AD: {ad_server} (StartTLS)")
    except Exception as exc:
        print(f"[WARN] StartTLS failed for {ad_server}: {exc}")

    return conn, base_dn


def change_ad_password(conn: Connection, base_dn: str, username: str, ad_pw: str) -> str:
    """
    Reset *username*'s AD password to *ad_pw* (prefix already included).

    Returns a short status string.
    """
    conn.search(
        search_base=base_dn,
        search_filter=f"(&(objectClass=user)(sAMAccountName={username}))",
        attributes=["distinguishedName"],
    )

    if not conn.entries:
        return "Not Found in AD"

    user_dn = conn.entries[0].distinguishedName.value
    try:
        result = ad_modify_password(conn, user_dn, ad_pw, None)
        return "Success" if result else "Failed"
    except Exception as exc:
        return f"Error: {exc}"



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rotate passwords in Nagios (webpass) and Active Directory."
    )
    parser.add_argument(
        "--network",
        required=True,
        choices=list(NETWORK_CONFIG.keys()),
        help="Target network (determines AD server and password prefix).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Only process the first N users (useful for test runs, e.g. --limit 1).",
    )
    args = parser.parse_args()
    network = args.network
    prefix  = NETWORK_CONFIG[network]["prefix"]

    users     = read_lines(USERS_FILE)
    passwords = read_lines(PASSWORD_FILE)

    if args.limit is not None:
        users = users[: args.limit]
        print(f"[INFO] Test mode : processing only {len(users)} user(s).")

    print(f"[INFO] Network  : {network}  (prefix: {prefix})")
    print(f"[INFO] Users    : {len(users)}")
    print(f"[INFO] Passwords: {len(passwords)}\n")
    session        = nagios_session()
    conn, base_dn  = ad_connection(network)

    
    output_file = os.path.join(SCRIPT_DIR, f"updated_passwords_{network}.csv")

    with open(output_file, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["username", "nagios_password", "ad_password", "nagios_status", "ad_status"])

        for index, username in enumerate(users, 1):
            print(f"[{index}/{len(users)}] {username}", end="  ")
            if username.lower() in NO_PASSWORD_CHANGE:
                print("-> SKIPPED (protected account)")
                writer.writerow([username, "", "", "Skipped", "Skipped"])
                continue

            base_pw = random.choice(passwords)
            ad_pw   = prefix + base_pw
            nagios_status = change_nagios_password(session, username, base_pw)
            ad_status     = change_ad_password(conn, base_dn, username, ad_pw)
            print(f"Nagios={nagios_status}  AD={ad_status}")
            writer.writerow([username, base_pw, ad_pw, nagios_status, ad_status])
            time.sleep(0.2)

    conn.unbind()
    print(f"\n[INFO] Done. Results written to: {output_file}")


if __name__ == "__main__":
    main()
