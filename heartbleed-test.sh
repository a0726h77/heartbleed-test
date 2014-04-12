#!/bin/bash

# INPUT=websites
INPUT=$1
while read website
do
    echo `date +"%F %T"`
    echo "Checking $website ..."
    # echo -e "quit\n" | openssl s_client -connect $website:443 -tlsextdebug 2>&1| grep 'TLS server extension "heartbeat" (id=15), len=1'
    python heartbleed-test.py $website
    echo "========"
done < $INPUT
