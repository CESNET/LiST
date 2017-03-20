#!/bin/sh

# This script expects one argument with
# maximal number of messages per second
# that is allowed to be dropped.

if [ $# -ne 1 ]; then
   echo Usage: `basename $0` maxlimit
   exit 3
fi

. $(dirname $0)/nemea_common.sh

pf="/tmp/`basename $0`-prevval"

curval="`get_data_ns | sed -n 's/^drop //p'`"
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

if test "$val" -lt "$1"; then
   echo "Drop threshold not reached."
   exit 0
else
   echo "More than $1 messages dropped."
   exit 2
fi
