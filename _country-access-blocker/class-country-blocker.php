<?php
/**
 * Country Access Blocker
 *
 * Core class that handles visitor country detection and access control.
 * Uses the country.is API for geolocation and maintains visitor statistics.
 *
 * @package		WordPress
 * @subpackage	Security\CountryBlocker
 * @since		1.9
 */

if (!defined('ABSPATH')) exit;

class CountryBlocker {
	/**
	 * The visitor's ip address
	 * @var	string
	 */
	private $visitor_ip;

	/**
	 * Base URL for the country.is API
	 * @var	string
	 */
	private $api_url = 'https://api.country.is/';

	/**
	 * Blocking message seen when access is denied
	 * @var	string
	 */
	private $block_message = 'Sorry, you are not allowed to access this page.';

	/**
	 * Static array to track processed IPs within a request
	 * @var	array
	 */
	private static $processed_ips = array();

	/**
	 * Singleton instance
	 * @var	CountryBlocker
	 */
	private static $instance = null;

	/**
	 * Initialize the plugin by setting up WordPress hooks
	 * 
	 * @param	string	$ip	Visitor's IP address
	 */
	private function __construct($ip) {
		$this->visitor_ip = $ip;
		
		// Initialize options if in admin area
		if (is_admin()) {
			$this->init_admin_settings();
		}
		
		// Add visitor check to init hook
		add_action('init', array($this, 'check_visitor'));
	}

	/**
	 * Get singleton instance
	 *
	 * @param	string	$ip	IP address for initialization
	 * @return	CountryBlocker
	 */
	public static function get_instance($ip = null) {
		if (self::$instance === null) {
			self::$instance = new self($ip);
		}
		return self::$instance;
	}

	/**
	 * Initialize plugin options
	 */
	private function init_admin_settings() {
		// Initialize the blocked countries option if it doesn't exist
		if (get_option(COUNTRY_BLOCKER_OPTIONS['blocked_countries']) === false) {
			add_option(COUNTRY_BLOCKER_OPTIONS['blocked_countries'], array());
		}
	}

	/**
	 * Logs API errors to debug.log
	 * @param	string	$message	The error that was thrown
	 * @param	string	$ip			The IP that threw the error
	 */
	private function log_api_error($message, $ip) {
		error_log(sprintf("%s - IP: %s - URI: %s - %s", 
			basename(__FILE__), 
			$ip,
			$_SERVER['REQUEST_URI'] ?? 'unknown',
			$message
		));
	}

	/**
	 * Retrieves the list of blocked countries from WordPress options.
	 * @return	array	List of blocked country codes
	 */
	private function get_blocked_countries() {
		$blocked = get_option(COUNTRY_BLOCKER_OPTIONS['blocked_countries']);
		if (!is_array($blocked)) {
			$blocked = array();
			update_option(COUNTRY_BLOCKER_OPTIONS['blocked_countries'], $blocked);
		}
		return $blocked;
	}

	/**
	 * Queries the country.is API to determine a visitor's country.
	 * @param	string	$ip		IP address to check
	 * @return	object|false	Country data object or false on failure
	 */
	private function get_visitor_country($ip) {
		// Check transient cache first
		$cache_key = 'country_blocker_' . md5($ip);
		$cached = get_transient($cache_key);
		if ($cached !== false) {
			return $cached;
		}

		// Add timeout to prevent hanging
		$args = array(
			'timeout' => 3.0,
			'httpversion' => '1.1',
			'headers' => array(
				'Accept' => 'application/json'
			)
		);

		$response = wp_remote_get($this->api_url . $ip, $args);
		
		// If there was an API error
		if (is_wp_error($response)) {
			$this->log_api_error(
				sprintf('API Error: %s', $response->get_error_message()),
				$ip
			);
			return false;
		}

		// If the response code was not 200
		$response_code = wp_remote_retrieve_response_code($response);
		if ($response_code !== 200) {
			$this->log_api_error(
				sprintf('API returned status code: %d', $response_code),
				$ip
			);
			return false;
		}

		// Parse JSON response
		$body = wp_remote_retrieve_body($response);
		$data = json_decode($body);

		// If the response was not properly formatted JSON
		if (json_last_error() !== JSON_ERROR_NONE) {
			$this->log_api_error(
				sprintf('Invalid JSON response: %s', json_last_error_msg()),
				$ip
			);
			return false;
		}

		// If there is no two-digit country code in the response
		if (!isset($data->country)) {
			$this->log_api_error(
				'API response missing country code',
				$ip
			);
			return false;
		}

		// Cache country code for 24 hours
		set_transient($cache_key, $data, DAY_IN_SECONDS);

		return $data;
	}

	/**
	 * Checks visitor's country and blocks access if necessary.
	 * This is the single place where country checking occurs.
	 */
	public function check_visitor() {
		// Skip if we've already processed this IP in this request
		if (in_array($this->visitor_ip, self::$processed_ips)) {
			return;
		}
		self::$processed_ips[] = $this->visitor_ip;

		$country_data = $this->get_visitor_country($this->visitor_ip);

		// If API call fails, allow access but error is already logged
		if (!$country_data) {
			return;
		}

		// Update visit statistics using database handler
		country_blocker_db()->update_visit_stats($country_data->country);
		
		// If we're an admin user and admin country isn't set, set it now
		if (current_user_can('manage_options') && !get_option(COUNTRY_BLOCKER_OPTIONS['admin_country'])) {
			add_option(COUNTRY_BLOCKER_OPTIONS['admin_country'], $country_data->country);
			return;
		}
		
		$blocked_countries = $this->get_blocked_countries();
		$admin_country = get_option(COUNTRY_BLOCKER_OPTIONS['admin_country']);
		
		// Never block the admin's country
		if ($admin_country) {
			$blocked_countries = array_diff($blocked_countries, array($admin_country));
		}
		
		// Check if visitor's country is blocked
		if (in_array($country_data->country, $blocked_countries)) {
			// Update blocked visit statistics using database handler
			country_blocker_db()->update_blocked_stats($country_data->country);
			wp_die($this->block_message, 'Access Denied', array('response' => 403));
		}
	}
}