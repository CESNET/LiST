#!/bin/sh

# This script expects one argument with
# minimal number of messages per second
# that is required to be sent in total.

if [ $# -ne 1 ]; then
   echo Usage: `basename $0` minlimit
   exit 3
fi

. ./nemea_common.sh

pf="$PREFIX/tmp/`basename $0`-prevval"

curval="`get_data_ns "ipfixcol_OUTIFC" | sed -n 's/^stat0 //p'`"
curtime="`date +%s`"
if [ -e "$pf" ]; then
   prevval="`cat "$pf" 2>/dev/null`"
else
   prevval="$curtime
$curval"
fi
prevtime="`echo "$prevval" | head -1`"
prevval="`echo "$prevval" | tail -n +2`"
echo "$curtime" > "$pf"
echo "$curval" >> "$pf"
curval="`echo "$curval" | tail -n +2`"

dtime="`absdiff "$curtime" "$prevtime"`"
if [ "$dtime" -eq 0 ]; then
   dtime=1
fi

ret="$(
paste <(echo "$curval") <(echo "$prevval") |
while read line; do
   a="`echo "$line" | cut -f1`"
   b="`echo "$line" | cut -f2`"
   val="`compute_rate_w "$a" "$b" "$dtime"`"
   if [ "$val" -lt "$1" ]; then
      echo 2
      break
   fi
done
)"

if [ -n "$ret" ]; then
   echo "ERROR"
   exit 2
else
   echo "OK"
   exit 0
fi

