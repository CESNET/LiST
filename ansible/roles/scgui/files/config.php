<?php

	/* =========== */
	/* ENVIRONMENT */
	/* =========== */
	$USE_LOCAL_TIME		= true; // Will use UTC if set to false
	$SINGLE_MACHINE		= true;	// Change this to true if you're running the whole SecurityCloud on the single machine. ($FDUMP will be called instead of $FDUMP_HA)
	$HISTORIC_DATA		= false; // Change this to true if this instance of GUI is supposed to analyze historical data
	$MAX_TABS 			= 8;	// Maximum of tabs for parallel fdistdump querries
	$USERSTAMP_LENGTH	= 16;	// Length of the userstamp identifying the transactions. The userstamp is a combination of symbols respecting the regex: [a-zA-Z0-9]

	/* =========== */
	/* EXECUTABLES */
	/* =========== */
	$FDUMP				= 'mpiexec -n 2 fdistdump_mpich'; // This is the path to your MPI binary and launch configuration. Also the path to the fdistdump binary has to be provided
	$FDUMP_HA			= 'fdistdump-ha';
	$FDUMP_ENV			= array('PATH' => '/usr/lib64/mpich/bin:/usr/local/bin:/bin:/usr/local/sbin:/usr/bin:/usr/sbin');
	$RRDTOOL			= '/opt/rrdtool-1.6.0/bin/rrdtool';	// Path to rrdtool

	/* =========== */
	/* DIRECTORIES */
	/* =========== */
	$BASE_DIR = '/var/www/html/scgui/web/';	// Full path to the index.php file of the GUI

	// Folder for storing transactions of the GUI.
	// User apache needs privileges to write into this
	// folder.
	$TMP_DIR			= '/tmp/scgui/';

	$IPFIXCOL_DATA		= '/data/flow/';					// Path to folder where query and graph data will be stored
	$IPFIXCOL_CFG		= '/etc/ipfixcol/profiles.xml';	// Path to the ipfixcol profile configuration file.

	// Path to the pidfile of the ipfixcol. This file has
	// to exist (and has to be valid) in order to reconfigure
	// collector on the run as the users create new profiles
	// in the gui.
	// ipfixcol is updated by sending SIGUSR1 to it's running process
	$PIDFILE = '/var/run/ipfixcol.pid';
?>
