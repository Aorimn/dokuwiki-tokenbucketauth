<?php

$conf['tba_block_time'] = 600;                // Block a user 10 minutes
$conf['tba_nb_attempt'] = 5;                  // If he failed 5 attempts to login
$conf['tba_mean_time']  = 120;                // Within 2 minutes
$conf['tba_whitelist']  = '127.0.0.1';        // And is not on the white list

$conf['tba_iptime_file'] = DOKU_PLUGIN.'tokenbucketauth/files/users.pbf'; // Log users attempts into this file
$conf['tba_block_file']  = DOKU_PLUGIN.'tokenbucketauth/files/block.pbf'; // Log blocked users into this one
$conf['tba_lockfile']    = DOKU_PLUGIN.'tokenbucketauth/files/lock.pbf';  // Lock file to know when we can put content into the two others

$conf['tba_send_mail']   = '';                // Send email to admins when a user has been banned, leave blank if to noone

