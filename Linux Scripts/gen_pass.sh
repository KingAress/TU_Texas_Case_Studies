
#!/bin/bash

WORDLIST_LOC="/home/simon/Documents/Selected_Topics_Scripts/wordlist.txt"

password=$(shuf -n 3 "$WORDLIST_LOC" | paste -sd '-' -)

echo "$password"
