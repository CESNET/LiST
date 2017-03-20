#!/bin/bash
#Checks free memory.
#If it is less than 10% of free memory it returns 2 as critical.

TOTAL=$(cat /proc/meminfo | grep MemTotal | tr -s ' ' | cut -d' ' -f2)
FREE=$(cat /proc/meminfo | grep MemAvailable | tr -s ' ' | cut -d' ' -f2)

#PERCENT of total memory used
PERCENT=$( echo "scale=2; (($TOTAL-$FREE)/$TOTAL)*100" | bc | cut -d'.' -f1)

if [ "$PERCENT" -lt "$1" ]; then
   echo "Memory OK."
   exit 0
fi
echo "Running out. Consuming $PERCENT% memory, limit is $1%."
exit 2
