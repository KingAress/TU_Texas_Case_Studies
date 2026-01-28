#!/bin/bash

#This script returns all users on a system that have password hashes
#This script can be run independently or part of a larger script network


FILENAME="$(hostname).txt"


#Extract users where the second field is not '!' or '*'
sudo awk -F: '$2 !~ /^(!|\*)$/ {print $1}' /etc/shadow > "$FILENAME"

echo "User list saved to $FILENAME"

