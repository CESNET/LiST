#!/bin/bash
# Debug purposes:
#exec >> /tmp/f2ban 2>> /tmp/f2ban.err

export TZ=UTC

filer_dir="/home/shared/warden/"
node_name=""
src_ip=""
failures=""
port_ssh="22"

printhelp()
{
   echo "$0 -i <attacker IP> -f <failures count> [-p PATH -P PORT -n NAME -d DETECTORIP]

-i IP address of the attacker (from Fail2Ban)
-f Number of failures (from Fail2Ban)
-p PATH Path to Warden client directory, /home/shared/warden by default
-P PORT Port of SSH server, 22 by default
-n NAME Node name to fill in into IDEA message, name of connector, taken from /etc/nemea/reporters-config.yml by default
-d DETECTORIP IP address of the server running Fail2Ban, taken from 'hostname -i' by default
-t TIMESTAMP Detection time in UNIX time, taken from Fil2Ban
-h Show this help
"
}

while getopts p:P:n:i:f:d:t:h optname; do
   case "$optname" in
   "p")
      if [ -n "$OPTARG" ]; then
      filer_dir="$OPTARG"
      fi
      ;;
   "P")
      if [ -n "$OPTARG" ]; then
      port_ssh="$OPTARG"
      fi
      ;;
   "n")
      if [ -n "$OPTARG" ]; then
      node_name="$OPTARG"
      fi
      ;;
   "i")
      if [ -n "$OPTARG" ]; then
      src_ip="$OPTARG"
      fi
      ;;
   "f")
      if [ -n "$OPTARG" ]; then
      failures="$OPTARG"
      fi
      ;;
   "t")
      if [ -n "$OPTARG" ]; then
      timestamp="$OPTARG"
      fi
      ;;
   "d")
      if [ -n "$OPTARG" ]; then
      target_ip4="$OPTARG"
      fi
      ;;
   *)
      printhelp
      exit 1
      ;;
   esac
done

if [ -z "$node_name" ]; then
   node_name="$(sed -n '/^namespace:/ s/namespace:\s*\(.*\)/\1.fail2ban/p' /etc/nemea/reporters-config.yml)"
   if [ -z "$node_name" ]; then
      echo Missing /etc/nemea/reporters-config.yml or -n parameter
      printhelp
      exit 1
   fi
fi

if [ -z "$target_ip4" ]; then
   target_ip4=$(/bin/hostname -i)
   if [ -z "$node_name" ]; then
      echo Missing detector\'s IP by hostname or -d parameter
      exit 1
   fi
fi

if [ -z "$src_ip" -o -z "$failures" -o -z "$timestamp" ]; then
   echo "Missing required information -i -f -t"
   exit 1
fi

detect_time=$(date --date="@$timestamp" --rfc-3339=seconds | sed 's/ /T/; s/+00:00/Z/;')
create_time=$(date --rfc-3339=seconds | sed 's/ /T/; s/+00:00/Z/;')

test -e "$filer_dir" || mkdir "$filer_dir"
test -e "$filer_dir"/temp ||  mkdir -p "$filer_dir/"temp
test -e "$filer_dir"/incoming ||  mkdir -p "$filer_dir/"incoming
test -e "$filer_dir"/errors ||  mkdir -p "$filer_dir/"errors

localuuid() {
        for ((n=0; n<16; n++)); do
                read -n1 c < /dev/urandom
                LC_CTYPE=C d=$(printf '%u' "'$c")
                s=''
                case $n in
                        6) ((d = d & 79 | 64));;
                        8) ((d = d & 191 | 128));;
                        3|5|9|7) s='-';;
                esac
                printf '%02x%s' $d "$s"
        done
}

event_id="$(uuidgen 2> /dev/null)"
[ -z "$event_id" ] && event_id="$(uuid 2> /dev/null)"
[ -z "$event_id" ] && event_id="$(localuuid 2> /dev/null)"

umask 0111

cat >"$filer_dir/temp/$event_id.idea" <<EOF
{
   "Format": "IDEA0",
   "ID": "$event_id",
   "DetectTime": "$detect_time",
   "CreateTime": "$create_time",
   "Category": ["Attempt.Login"],
   "Description": "SSH dictionary/bruteforce attack",
   "ConnCount": $failures,
   "Note": "IP attempted $failures logins to SSH service",
   "Source": [{
      "IP4": ["$src_ip"],
      "Proto": ["tcp", "ssh"]
   }],
   "Target": [{
       "IP4": ["$target_ip4"],
       "Proto": ["tcp", "ssh"],
       "Port": [$port_ssh]
   }],
   "Node": [{
         "Name": "$node_name",
         "SW": ["Fail2Ban"],
         "Type": ["Log", "Statistical"]
   }]
}
EOF

mv "$filer_dir/temp/$event_id.idea" "$filer_dir/incoming/"

