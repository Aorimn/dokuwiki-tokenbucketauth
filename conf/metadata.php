<?php

$meta['tba_block_time']  = array('numeric');  // Block an IP address a certain amount of seconds
$meta['tba_nb_attempt']  = array('numeric');  // If the user failed a certain amount of attempts to login
$meta['tba_mean_time']   = array('numeric');  // Within a certain amount of seconds
$meta['tba_whitelist']   = array('string');   // And is not on the white list

$meta['tba_iptime_file'] = array('string');   // Log users attempts into this file
$meta['tba_block_file']  = array('string');   // Log blocked users into this one
$meta['tba_lockfile']    = array('string');   // Lock file to know when we can put content into the two others

$meta['tba_send_mail']   = array('email');    // Define whom to send email when a user has been banned

$meta['tba_block_whole_wiki'] = array('onoff'); // Define whether to block the whole wiki or just the login page
