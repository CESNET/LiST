<?php

//error_reporting(E_ALL);
//ini_set('display_errors', 1);

$BASE_DIR = '/var/www/html/scgui/web/';
$MAX_TABS = 8;
$FDUMP = '/usr/lib64/mpich/bin/mpiexec -n 2 /usr/lib64/mpich/bin/fdistdump_mpich';
$SINGLE_MACHINE = true;
$RRDTOOL = '/opt/rrdtool-1.6.0/bin/rrdtool';
$USERSTAMP_LENGTH = 16;
$TMP_DIR = '/tmp/scgui/';
$IPFIXCOL_DATA = '/data/flow/';
$IPFIXCOL_CFG = '/etc/ipfixcol/profiles.xml';
$PIDFILE = '/var/run/ipfixcol.pid';
?>
