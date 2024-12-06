<?php
/**
 * Country Access Blocker Loader
 *
 * @package		WordPress
 * @subpackage	Security\CountryBlocker
 * @since		1.9
 * 
 * @wordpress-plugin
 * Plugin Name:	Country Access Blocker
 * Description:	Blocks website access based on visitor country of origin using the 'country.is' API. 
 *				Maintains aggregate statistics of visits per country and allows administrators to 
 *				block specific countries while protecting admin access.
 * Version:		1.9
 * Author:		Mark Tomlinson and Anthropic Claude
 * License:		GPLv2 or later
 * License URI:	https://www.gnu.org/licenses/gpl-2.0.html

 */

if (!defined('ABSPATH')) exit;

// Load the database handler class
require_once __DIR__ . '/_country-access-blocker/class-country-blocker-db.php';

// Define plugin constants
define('COUNTRY_BLOCKER_VERSION', '1.9');
define('COUNTRY_BLOCKER_PATH', __DIR__ . '/_country-access-blocker');
define('COUNTRY_BLOCKER_OPTIONS', [
	'blocked_countries' => 'country_blocker_blacklist',
	'admin_country' => 'country_blocker_admin_country'
]);

/**
 * Provides global access to the database handler instance
 * @return	CountryBlockerDB	Database handler instance
 */
function country_blocker_db() {
	return CountryBlockerDB::get_instance();
}

// Initialize database if needed
$db = country_blocker_db();
if (!$db->table_exists()) {
	$db->initialize_table();
}

/**
 * Determines if an IP address is from a private network
 * @param	string	$ip	IP address to check
 * @return	boolean		True if IP is internal/private
 */
function is_internal_ip($ip) {
	// Check if it's a valid IP at all (v4 or v6)
	if (!filter_var($ip, FILTER_VALIDATE_IP)) {
		return true;	// Invalid IP format, treat as internal
	}
	// For both IPv4 and IPv6, check if it's not a public address
	return !filter_var($ip, 
		FILTER_VALIDATE_IP, 
		FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
	);
}

// Get visitor's IP
$visitor_ip = !empty($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

// Only load frontend blocking for public IPs
if (!is_internal_ip($visitor_ip)) {
	require_once COUNTRY_BLOCKER_PATH . '/class-country-blocker.php';
	CountryBlocker::get_instance($visitor_ip);
}

// Load admin functionality in admin area regardless of IP
if (is_admin()) {
	require_once COUNTRY_BLOCKER_PATH . '/class-country-blocker-admin.php';
	new CountryBlockerAdmin();
}