#!/bin/bash

# Define output file
OUTFILE="suspicious_users.txt"

# 1. Extract UIDs and find duplicates
# 2. Loop through duplicates and find the associated usernames
awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read -r uid; do
    echo "Duplicate UID found: $uid"
    grep ":x:$uid:" /etc/passwd | cut -d: -f1,3 >> "$OUTFILE"
done

# Check if the file was created; if not, no duplicates were found
if [ -f "$OUTFILE" ]; then
    echo "Done. Results saved to $OUTFILE"
else
    echo "No duplicate UIDs detected."
fi
