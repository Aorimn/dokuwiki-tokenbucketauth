<?php
/**
 * Cf licence informations in README
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC'))
	die('yeurk!');

if(!defined('DOKU_PLUGIN'))
	define('DOKU_PLUGIN', DOKU_INC . 'lib/plugins/');

require_once(DOKU_PLUGIN . 'admin.php');


/**
 * All DokuWiki plugins to extend the admin function
 * need to inherit from this class
 */
class admin_plugin_tokenbucketauth extends DokuWiki_Admin_Plugin
{
	/**
	 * access for managers
	 */
	function forAdminOnly()
	{
		return false;
	}

	/**
	 * return sort order for position in admin menu
	 */
	function getMenuSort()
	{
		return 42;
	}

	/**
	 * handle user request
	 */
	function handle()
	{
		global $conf;

		if(empty($_REQUEST['tba__delete_ip']))
			return;

		if(empty($_REQUEST['delip']) || !is_array($_REQUEST['delip']))
			return;

		/* Get the IP address */
		$ip = array_shift(array_keys($_REQUEST['delip']));

		$lockf = $conf['cachedir'] . '/' . $this->getConf('tba_lockfile');
		$banned_f  = $conf['cachedir'] . '/' . $this->getConf('tba_block_file');
		
		/* Lock the file for writing */
		$lockfh = fopen($lockf, 'w', false);

		if($lockfh === false)
			return;

		if(flock($lockfh, LOCK_EX) === false)
		{
			fclose($lockfh);
			return;
		}

		/* Open the file to search for the $ip to delete */
		$content = file_get_contents($banned_f);

		if(empty($content))
		{
			flock($lockfh, LOCK_UN);
			fclose($lockfh);

			msg(sprintf($this->getLang('del_ipnotfound'), $ip), -1);
			return;
		}
		else
			$blocked = @unserialize($content);

		/* Deal with the case of unserialize() failing */
		if($blocked === false || !is_array($blocked))
		{
			flock($lockfh, LOCK_UN);
			fclose($lockfh);
			return;
		}

		if(isset($blocked[$ip]))
		{
			/* Remove the banned IP */
			unset($blocked[$ip]);

			/* Save the blocked-IP file */
			io_saveFile($banned_f, serialize($blocked));

			/* Remove any occurrence of this IP address in the tracker file */
			$track_f = $conf['cachedir'] . '/' . $this->getConf('tba_iptime_file');
			$content = file_get_contents($track_f);
			$user_tracker = null;

			if(empty($content))
				$users_tracker = array();
			else
				$users_tracker = @unserialize($content);

			if($users_tracker === false)
				$users_tracker = array();

			if(isset($users_tracker[$ip]))
				unset($users_tracker[$ip]);

			io_saveFile($track_f, serialize($users_tracker));

			msg(sprintf($this->getLang('del_success'), $ip), 1);
		}
		else
			msg(sprintf($this->getLang('del_ipnotfound'), $ip), -1);

		flock($lockfh, LOCK_UN);
		fclose($lockfh);
	}

	/**
	 * output appropriate html
	 */
	function html()
	{
		global $conf;

		$banned_f = $conf['cachedir'] . '/' . $this->getConf('tba_block_file');
		$bans = @file_get_contents($banned_f);

		if(empty($bans))
			$bans = array();
		else
			$bans = @unserialize($bans);

		/* Deal with the case of unserialize() failing */
		if($bans === false)
			$bans = array();

		/* Get the current time once and for all */
		$curr_time = time();
		$ban_time  = $this->getConf('tba_block_time');

		/* Remove IP which have their ban expired */
		$new_bans = array();
		foreach($bans as $ip => $block_timestamp)
		{
			if($block_timestamp + $ban_time < $curr_time)
				continue;

			$new_bans[$ip] = $block_timestamp;
		}
		$bans = $new_bans;

		/* Now fill the admin panel */
		echo $this->locale_xhtml('admin_intro');

		echo '<form method="post" action="">';
		echo '<table class="inline" width="100%">';
		echo '<tr>';
		echo '<th>'.$this->getLang('ip').'</th>';
		echo '<th>'.$this->getLang('host').'</th>';
		echo '<th>'.$this->getLang('date').'</th>';
		echo '<th>'.$this->getLang('del').'</th>';
		echo '</tr>';

		if(!empty($bans) && is_array($bans))
		{
			foreach($bans as $ip => $block_timestamp)
			{
				$host = @gethostbyaddr($ip);
				if($host === false || $host === $ip)
					$host = '?';

				echo '<tr>';
				echo '<td>'.$ip.'</td>';
				echo '<td>'.hsc($host).'</td>';
				echo '<td>'.strftime($conf['dformat'], $block_timestamp).'</td>';
				echo '<td><input type="submit" name="delip['.$ip.']" value="'.hsc($this->getLang('del')).'" class="button" /></td>';
				echo '</tr>';
			}
		}
		else
		{
			echo '<tr>';
			echo '<td colspan="4" style="text-align:center; font-style: italic">' . hsc($this->getLang('noban')) . '</td>';
			echo '</tr>';
		}
		echo '</table>';
		echo '<input type="hidden" name="tba__delete_ip" value="1" />';
		echo '</form>';
	}
}
