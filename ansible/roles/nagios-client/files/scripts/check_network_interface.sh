#!/bin/bash
#Checks errors on used network interface. If errors are found it returns 2 as critical.

. nemea_common.sh

pf="/tmp/`basename $0`-prevval"

#addding up errors for all network interfaces
curval="`netstat -i | awk 'NR>=3 {i+=$5} END{print i}'`"
curtime="`date +%s`"

if [ -e "$pf" ]
then
   prevval="`cat "$pf" | head -1`"
else
   prevval="$curval $curtime"
fi

prevtime="`echo "$prevval" | cut -d' ' -f2`"
prevval="`echo "$prevval" | cut -d' ' -f1`"
echo "$curval $curtime" > "$pf"

val="`compute_rate "$curval" "$prevval" "$curtime" "$prevtime"`"

if [ "$val" -ne 0 ]
then
   echo "Error occured on at least one interface."
   exit 2
else
   echo "No errors."
   exit 0
fi
