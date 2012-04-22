<?php

$conf['pbf_block_time'] = 600;                // Block a user 10 minutes
$conf['pbf_nb_attempt'] = 5;                  // If he failed 5 attempts to login
$conf['pbf_mean_time']  = 120;                // Within 2 minutes
$conf['pbf_whitelist']  = array('127.0.0.1'); // And is not on the white list

$conf['pbf_iptime_file'] = DOKU_PLUGIN.'preventbruteforce/files/users.pbf'; // Log users attempts into this file
$conf['pbf_block_file']  = DOKU_PLUGIN.'preventbruteforce/files/block.pbf'; // Log blocked users into this one
$conf['pbf_lockfile']    = DOKU_PLUGIN.'preventbruteforce/files/lock.pbf';  // Lock file to know when we can put content into the two others

$conf['pbf_send_mail']   = '';                // Send email to admins when a user has been banned, leave blank if to noone

