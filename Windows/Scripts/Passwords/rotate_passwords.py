import argparse
import base64
import csv
import getpass
import os
import random
import subprocess
import sys
import time

import paramiko
import requests
from bs4 import BeautifulSoup

# type "windows" PowerShell Set-ADAccountPassword
# type "linux"   SSH into samba_host, run samba-tool user setpassword
NETWORK_CONFIG = {
    "steel":  {"type": "windows", "ad_server": "steel.texas.tu",       "prefix": "3eJ"},
    "aero":   {"type": "windows", "ad_server": "aero.texas.tu",        "prefix": "E2L"},
    "auto":   {"type": "windows", "ad_server": "auto.texas.tu",        "prefix": "qR#"},
    "mining": {"type": "linux",   "samba_host": "172.18.101.127",      "prefix": "fq*",
               "ssh_user": "root", "samba_tool": "/usr/bin/samba-tool"},
    "chem":   {"type": "linux",   "samba_host": "172.18.131.239",      "prefix": "5M0",
               "ssh_user": "root", "samba_tool": "/usr/bin/samba-tool"},
}

WEBPASS_LOGIN_URL = "http://webapps.classex.tu/webpass/"
PASSWORD_PAGE     = "http://webapps.classex.tu/webpass/index.php"

TEAM_NAME = os.getenv("TEAM_NAME", "texas")

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
USERS_FILE    = os.path.join(SCRIPT_DIR, "Users", "users.txt")
PASSWORD_FILE = os.path.join(SCRIPT_DIR, "passwords.txt")

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


def read_lines(filepath: str) -> list[str]:
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)




def nagios_session(team_password: str) -> requests.Session:
    session = requests.Session()
    session.verify = False
    try:
        resp = session.post(
            WEBPASS_LOGIN_URL,
            data={"team": TEAM_NAME, "password": team_password},
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
    
    try:
        page = session.get(PASSWORD_PAGE, timeout=15)
        soup = BeautifulSoup(page.text, "html.parser")

        form_data: dict[str, str] = {}
        for inp in soup.find_all("input"):
            name = inp.get("name")
            if name:
                form_data[name] = inp.get("value", "")

        form_data["user"]      = username
        form_data["password1"] = base_pw
        form_data["password2"] = base_pw

        resp = session.post(PASSWORD_PAGE, data=form_data, timeout=15)
        return "Success" if resp.status_code == 200 else f"HTTP {resp.status_code}"

    except requests.RequestException as exc:
        return f"Error: {exc}"




def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode("ascii")


def change_ad_password(
    ad_server: str,
    ad_user: str,
    ad_admin_password: str,
    username: str,
    ad_pw: str,
) -> str:
    admin_b64 = _b64(ad_admin_password)
    newpw_b64 = _b64(ad_pw)

    ps_script = f"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'

$adminPass = [System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String('{admin_b64}')
) | ConvertTo-SecureString -AsPlainText -Force

$cred = New-Object System.Management.Automation.PSCredential('{ad_user}', $adminPass)

$newPass = [System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String('{newpw_b64}')
) | ConvertTo-SecureString -AsPlainText -Force

try {{
    Set-ADAccountPassword -Identity '{username}' `
        -NewPassword $newPass `
        -Reset `
        -Credential $cred `
        -Server '{ad_server}'
    Write-Output 'AD_SUCCESS'
}} catch {{
    Write-Output "AD_FAILED: $($_.Exception.Message)"
}}
"""
    try:
        ps_encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-OutputFormat", "Text", "-EncodedCommand", ps_encoded],
            capture_output=True,
            text=True,
            timeout=30,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if "AD_SUCCESS" in stdout:
            return "Success"

        # Strip CLIXML serialization from stderr if present
        if stderr.startswith("#< CLIXML"):
            import re
            msgs = re.findall(r'<S S="Error">(.*?)</S>', stderr)
            stderr = " ".join(m.replace("_x000D__x000A_", "") for m in msgs).strip()

        detail = (stderr or stdout or f"exit code {result.returncode}")[:200]
        return f"Failed: {detail}"
    except subprocess.TimeoutExpired:
        return "Error: PowerShell timeout"
    except Exception as exc:
        return f"Error: {exc}"




def open_ssh(host: str, ssh_user: str, ssh_password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=ssh_user,
        password=ssh_password,
        timeout=15,
        look_for_keys=True,
        allow_agent=True,
    )
    return client


def change_samba_password(
    ssh: paramiko.SSHClient,
    samba_tool: str,
    username: str,
    ad_pw: str,
) -> str:
    safe_pw = ad_pw.replace("'", "'\\''")
    cmd = f"{samba_tool} user setpassword '{username}' --newpassword='{safe_pw}'"
    try:
        _, stdout, stderr = ssh.exec_command(cmd, timeout=20)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if exit_code == 0:
            return "Success"
        return f"Failed: {(err or out)[:150]}"
    except Exception as exc:
        return f"Error: {exc}"




def run_single_network(
    network: str,
    users: list[str],
    passwords: list[str],
    team_password: str,
    skip_nagios: bool = False,
    existing_pw_map: dict[str, str] | None = None,
) -> dict[str, str]:
    """
    Process one network. Returns {username: base_password} for reuse.
    If existing_pw_map is provided the same base passwords are used (skip Nagios re-run).
    """
    cfg    = NETWORK_CONFIG[network]
    prefix = cfg["prefix"]
    net_type = cfg["type"]  

    if net_type == "windows":
        ad_user = input(f"\n[{network.upper()}] AD username (e.g. {network}\\administrator): ").strip()
        ad_pass = getpass.getpass(f"[{network.upper()}] AD password for {ad_user}: ")
        ssh_client = None
    else:
        ssh_host  = cfg["samba_host"]
        ssh_user  = cfg.get("ssh_user", "root")
        ssh_pass  = getpass.getpass(f"\n[{network.upper()}] SSH password for {ssh_user}@{ssh_host}: ")
        samba_tool = cfg.get("samba_tool", "/usr/bin/samba-tool")
        print(f"[{network.upper()}] Connecting via SSH to {ssh_host}...")
        try:
            ssh_client = open_ssh(ssh_host, ssh_user, ssh_pass)
            print(f"[{network.upper()}] SSH connected.")
        except Exception as exc:
            print(f"[ERROR] SSH connection failed: {exc}")
            sys.exit(1)

    session     = nagios_session(team_password) if not skip_nagios else None
    pw_map      = existing_pw_map or {}
    output_file = os.path.join(SCRIPT_DIR, f"updated_passwords_{network}.csv")

    with open(output_file, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["username", "nagios_password", "ad_password", "nagios_status", "ad_status"])

        for index, username in enumerate(users, 1):
            print(f"  [{index}/{len(users)}] {username}", end="  ")

            if username.lower() in NO_PASSWORD_CHANGE:
                print("-> SKIPPED")
                writer.writerow([username, "", "", "Skipped", "Skipped"])
                continue

            base_pw = pw_map.get(username) or random.choice(passwords)
            pw_map[username] = base_pw
            ad_pw = prefix + base_pw

            nagios_status = (
                change_nagios_password(session, username, base_pw)
                if not skip_nagios
                else "Skipped (reuse)"
            )

            if net_type == "windows":
                ad_status = change_ad_password(cfg["ad_server"], ad_user, ad_pass, username, ad_pw)
            else:
                ad_status = change_samba_password(ssh_client, samba_tool, username, ad_pw)

            print(f"Nagios={nagios_status}  AD={ad_status}")
            writer.writerow([username, base_pw, ad_pw, nagios_status, ad_status])
            time.sleep(0.2)

    if ssh_client:
        ssh_client.close()

    print(f"  -> Results: {output_file}")
    return pw_map


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rotate passwords in Nagios (webpass) and Active Directory."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--network",
        choices=list(NETWORK_CONFIG.keys()),
        help="Process a single network.",
    )
    mode.add_argument(
        "--all-networks",
        action="store_true",
        help="Process ALL networks. Nagios is updated once; each domain's AD is "
             "updated with its own prefix. You will be prompted for AD credentials "
             "per domain.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Only process the first N users (test mode).",
    )
    parser.add_argument(
        "--user",
        default=None,
        metavar="USERNAME",
        help="Process a single specific user instead of users.txt.",
    )
    args = parser.parse_args()

    team_password = getpass.getpass("Webpass team password: ")

    passwords = read_lines(PASSWORD_FILE)
    if args.user:
        users = [args.user]
        print(f"[INFO] Single-user mode: {args.user}")
    else:
        users = read_lines(USERS_FILE)

    if args.limit is not None:
        users = users[: args.limit]
        print(f"[INFO] Limit mode: processing only {len(users)} user(s).")

    print(f"[INFO] Users    : {len(users)}")
    print(f"[INFO] Passwords: {len(passwords)}")

    if args.all_networks:
        print("\n[INFO] ALL-NETWORKS mode:")
        print("  - Nagios passwords set ONCE using the first network's run.")
        print("  - Each AD domain gets the same base password + its own prefix.")
        print("  - You will be prompted for AD credentials for each domain.\n")

        pw_map: dict[str, str] = {}
        for i, network in enumerate(NETWORK_CONFIG):
            print(f"\n{'='*50}")
            print(f"  Network {i+1}/{len(NETWORK_CONFIG)}: {network.upper()}  "
                  f"(prefix: {NETWORK_CONFIG[network]['prefix']})")
            print(f"{'='*50}")
            skip_nagios = i > 0  # Only set Nagios on the first network pass
            pw_map = run_single_network(
                network, users, passwords, team_password,
                skip_nagios=skip_nagios,
                existing_pw_map=pw_map if i > 0 else None,
            )

        print("\n[INFO] All networks complete.")

    else:
        network = args.network
        print(f"[INFO] Network  : {network}  (prefix: {NETWORK_CONFIG[network]['prefix']})")
        run_single_network(network, users, passwords, team_password)
        print("\n[INFO] Done.")


if __name__ == "__main__":
    main()
