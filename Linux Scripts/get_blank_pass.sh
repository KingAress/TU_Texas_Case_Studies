#!/bin/bash
# Identify accounts that have no password set
OUT="empty_passwords.txt"

sudo awk -F: '$2 == "" {print $1}' /etc/shadow > "$OUT"

if [ -s "$OUT" ]; then
    echo "[!] WARNING: Accounts with empty passwords found!"
    cat "$OUT"
else
    echo "[+] No accounts with empty passwords detected."
    rm "$OUT"
fi
