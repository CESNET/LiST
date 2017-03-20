#!/bin/bash
#checks whether nemea-supervisor is running

service nemea-supervisor status > /dev/null 2> /dev/null
ret=$?

if [ "$ret" -eq 0 ]; then
   echo "Supervisor UP."
   exit 0
else
   echo "Supervisor DOWN."
   exit 2
fi
