#!/bin/bash

INPUT="users.txt"

while IFS= read USER
do
        echo "Creating user: $USER"
        useradd -m -s /bin/bash "$USER"


        echo "$USER:password1!" | chpasswd
        passwd -e "$USER"

done < "$INPUT"
echo "Done!"

