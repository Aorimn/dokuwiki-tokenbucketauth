<?php

/**
 * Prevent against bruteforce attacks
 *
 * @license    GPL 3 (http://www.gnu.org/licenses/gpl.html)
 * @author     Aorimn <Aorimn@giboulees.net>
 * @version    0.4
 */

/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3, 
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * The license for this software can likely be found here: 
 * http://www.gnu.org/licenses/gpl-3.0.html
 */


// must be run within Dokuwiki
if(!defined('DOKU_INC'))
	die('yeurk!');
if(!defined('DOKU_PLUGIN'))
	define('DOKU_PLUGIN', DOKU_INC . 'lib/plugins/');

require_once(DOKU_PLUGIN . 'action.php');


class action_plugin_tokenbucketauth extends DokuWiki_Action_Plugin
{
	/** Lock file */
	protected $lockfh;

	/** Array of IPs=>[visited_time1,visited_time2,...] */
	protected $users_tracker;

	/** Array of blocked IP addresses => when_blocked_timestamp */
	protected $blocked;

	/**
	 * Constructor, initialize class' variables
	 */
	function __construct()
	{
		$this->lockfh        = null;
		$this->users_tracker = null;
		$this->blocked       = null;
	}

	/**
	 * Register plugin's handlers
	 */
	public function register(&$controller)
	{
		$controller->register_hook('DOKUWIKI_STARTED', 'BEFORE', $this, 'disable_login', array());
		$controller->register_hook('AUTH_LOGIN_CHECK', 'AFTER', $this, 'register_login_fail', array());
	}

	/**
	 * Look if we have to disable login for this particuliar IP address
	 */
	public function disable_login(&$event, $param)
	{
		global $ACT, $conf;

		if($ACT === 'login' || !$this->getConf('tba_block_login_only'))
		{
			$this->lock();

			$content = '';
			$file    = $conf['cachedir'] . '/' . $this->getConf('tba_block_file');

			/* Get the users which are blocked */
			if(is_readable($file))
				$content = file_get_contents($file);

			if(empty($content))
				$this->blocked = array();
			else
				$this->blocked = @unserialize($content);

			/* Deal with the case of unserialize() failing */
			if($this->blocked === false)
				$this->blocked = array();

			$ip   = $_SERVER['REMOTE_ADDR'];
			$time = time();

			/* If the user come from a whitelisted address */
			if(in_array($ip, preg_split('/[\s,]+/', $this->getConf('tba_whitelist'), null, PREG_SPLIT_NO_EMPTY)))
			{
				$this->unlock();
				return;
			}

			/* If the user is already blocked */
			if(array_key_exists($ip, $this->blocked))
			{
				if($this->blocked[$ip] + $this->getConf('tba_block_time') > $time)
				{
					/* If the time isn't elapsed yet */
					$this->_do_disable_login();
					$this->unlock();
					return;
				}
				else
				{
					/* If the user is no longer banned */
					unset($this->blocked[$ip]);
				}
			}

			$ts   = $this->users_tracker[$ip];
			$time = $time - $this->getConf('tba_mean_time');
			$max  = $this->getConf('tba_nb_attempt');
			$cpt  = 0;

			$i        = 0;
			$to_unset = array();

			/* Check whether to block or not the IP */
			if(!is_null($ts))
			{
				foreach($ts as $onets)
				{
					if($time < $onets)
						$cpt++;
					else
						$to_unset[] = $i;

					$i++;
				}
			}

			/* Clean old timestamps */
			foreach($to_unset as $i)
				unset($ts[$i]);

			/* Update the tracker array */
			$this->users_tracker[$ip] = $ts;

			/* If there's more attempts than authorized, block the IP */
			if($cpt >= $max)
				$this->blocked[$ip] = $time + $this->getConf('tba_mean_time');

			/* Save the timestamps file */
			io_saveFile($conf['cachedir'] . '/' . $this->getConf('tba_iptime_file'), serialize($this->users_tracker));

			/* Save the blocked-IP file */
			io_saveFile($file, serialize($this->blocked));

			/* Don't forget to unlock */
			$this->unlock();

			if(array_key_exists($ip, $this->blocked))
				$this->_do_disable_login($ip);
		}
	}

	/**
	 * Register failed attempts to login
	 */
	public function register_login_fail(&$event, $param)
	{
		global $ACT, $conf;

		if($ACT === 'login' && !empty($event->data['user']) && !isset($_SESSION['REMOTE_USER']))
		{
			$this->lock();

			$content = '';
			$file = $conf['cachedir'] . '/' . $this->getConf('tba_iptime_file');

			/* Get the previous, the registered array of visits */
			if(is_readable($file))
				$content = file_get_contents($file);
			
			/* Initialize from the file or not */
			if(empty($content))
				$this->users_tracker = array();
			else
				$this->users_tracker = @unserialize($content);

			/* Deal with the case of unserialize() failing */
			if($this->users_tracker === false)
				$this->users_tracker = array();

			$ip   = $_SERVER['REMOTE_ADDR'];
			$time = time();

			/* Add an entry for this visit */
			if(empty($this->users_tracker[$ip]))
				$this->users_tracker[$ip]   = array($time);
			else
				$this->users_tracker[$ip][] = $time;

			/* Save the file */
			io_saveFile($file, serialize($this->users_tracker));

			/* Don't forget to unlock */
			$this->unlock();
		}
	}

	/**
	 * Use a lock file not to update files concurrently
	 */
	protected function lock()
	{
		global $conf;

		$lockf = $conf['cachedir'] . '/' . $this->getConf('tba_lockfile');

		$this->lockfh = fopen($lockf, 'w', false);

		if($this->lockfh === false)
			return false;

		if(flock($this->lockfh, LOCK_EX) === false)
		{
			fclose($this->lockfh);
			$this->lockfh = null;
			return false;
		}

		return true;
	}

	/**
	 * Unlock previously locked file
	 */
	protected function unlock()
	{
		if(!is_null($this->lockfh))
		{
			flock($this->lockfh, LOCK_UN);
			fclose($this->lockfh);
			$this->lockfh = null;
		}
	}

	/**
	 * Change the login action to the show one
	 *
	 * @param $new False if it's not a new IP which is banned, the new banned IP otherwise
	 */
	protected function _do_disable_login($new = false)
	{
		global $conf;

		# TODO add languages things

		header("HTTP/1.0 403 Forbidden");
		echo<<<EOT
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<head><title>Access denied</title></head>
<body style="font-family: Arial, sans-serif">
  <div style="width:60%; margin: auto; background-color: #fcc;
              border: 1px solid #faa; padding: 0.5em 1em;">
  Get off!
  </div>
</body>
</html>
EOT;

		// Send email for a new banned IP address
		$email = $this->getConf('tba_send_mail');
		if(!empty($email) && $new && !empty($new))
		{
			// Prepare fields
			$subject = sprintf($this->getLang('mailsubject'), $conf['title']);
			$body    = $this->plugin_locale_xhtml('mailbody');
			$from    = $conf['mailfrom'];

			// Do some replacements
			$body = str_replace('@IP@', $new, $body);
			$body = str_replace('@DOKUWIKIURL@', DOKU_URL, $body);

			// Finally send mail
			mail_send($email, $subject, $body, $from);
		}

		exit;
	}
}

