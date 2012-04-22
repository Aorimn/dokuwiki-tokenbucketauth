<?php

$meta['pbf_block_time']  = array('numeric');  // Block an IP address a certain amount of seconds
$meta['pbf_nb_attempt']  = array('numeric');  // If the user failed a certain amount of attempts to login
$meta['pbf_mean_time']   = array('numeric');  // Within a certain amount of seconds
$meta['pbf_whitelist']   = array('string');   // And is not on the white list

$meta['pbf_iptime_file'] = array('string');   // Log users attempts into this file
$meta['pbf_block_file']  = array('string');   // Log blocked users into this one
$meta['pbf_lockfile']    = array('string');   // Lock file to know when we can put content into the two others

$meta['pbf_send_mail']   = array('email');    // Define whom to send email when a user has been banned

