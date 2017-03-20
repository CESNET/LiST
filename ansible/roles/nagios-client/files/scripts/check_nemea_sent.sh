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

curval="`get_data_ns "nemea_ifcs_total" | sed -n 's/^sent //p'`"
curtime="`date +%s`"
if [ -e "$pf" ]; then
   prevval="`cat "$pf" 2>/dev/null| head -1`"
else
   prevval="$curval $curtime"
fi
prevtime="`echo "$prevval" | cut -d' ' -f2`"
prevval="`echo "$prevval" | cut -d' ' -f1`"
echo "$curval $curtime" > "$pf"

val="`compute_rate "$curval" "$prevval" "$curtime" "$prevtime"`"

if test "$val" -gt "$1"; then
   echo "Enough messages being sent."
   exit 0
else
   echo "Less than $1 messages was sent."
   exit 2
fi

