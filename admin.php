<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC'))
	die();

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
		$file  = $conf['cachedir'] . '/' . $this->getConf('tba_block_file');
		
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
		$content = file_get_contents($file);

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
			io_saveFile($file, serialize($blocked));

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

		$file = $conf['cachedir'] . '/' . $this->getConf('tba_block_file');
		$bans = @file_get_contents($file);

		if(empty($bans))
			$bans = array();
		else
			$bans = @unserialize($bans);

		/* Deal with the case of unserialize() failing */
		if($bans === false)
			$bans = array();

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
				# TODO remove IP if the ban is already done (check $block_timestamp)

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
			echo '<td colspan="4">' . hsc($this->getLang('noban')) . '</td>';
			echo '</tr>';
		}
		echo '</table>';
		echo '<input type="hidden" name="tba__delete_ip" value="1" />';
		echo '</form>';
	}
}
