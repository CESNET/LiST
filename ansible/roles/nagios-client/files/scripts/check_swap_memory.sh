#!/bin/bash
#Checks swap memory.
#If there is more than 20% used it returns 2 as critical.

TOTAL=$(cat /proc/meminfo | grep SwapTotal | tr -s ' ' | cut -d' ' -f2)
FREE=$(cat /proc/meminfo | grep SwapFree | tr -s ' ' | cut -d' ' -f2)

if [ "$TOTAL" -eq 0 ]; then
  echo "Swap memory disabled."
  exit 1
fi

PERCENT=$( echo "scale=2; ($TOTAL-$FREE/$TOTAL)*100" | bc | cut -d'.' -f1)

if [ "$PERCENT" -gt 80 ]; then
   echo "OK."
   exit 0
else
   echo "Running out. More than 80% used"
   exit 2
fi
