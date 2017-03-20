#!/bin/sh

get_data_ns()
{
(
    /usr/share/munin/plugins/nemea_supervisor
) | sed -n "/^multigraph $1/,/^$/ s/^\(.*\)\.value \(.*\)/\1 \2/p"
}

absdiff()
{
    if [ "$1" -gt "$2" ]; then
        expr "$1" - "$2"
    else
        expr "$2" - "$1"
    fi
}

compute_rate()
{
    delta=`absdiff "$1" "$2"`
    deltat=`absdiff "$3" "$4"`
    if [ "$deltat" -ne 0 ]; then
        expr "$delta" / "$deltat"
    else
        echo "$delta"
    fi
}

compute_rate_w()
{
    delta=`absdiff "$1" "$2"`
    if [ "$3" -ne 0 ]; then
        expr "$delta" / "$3"
    else
        echo "$delta"
    fi
}
