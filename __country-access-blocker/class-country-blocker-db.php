<?php
/**
 * Country Access Blocker Database Handler
 *
 * Centralizes all database operations for the Country Access Blocker plugin.
 * Follows Single Responsibility Principle by handling only database operations.
 *
 * @package		WordPress
 * @subpackage	Security\CountryBlocker
 * @since		1.9
 */

if (!defined('ABSPATH')) exit;

class CountryBlockerDB {
	/**
	 * Table name for visitor statistics
	 * @var	string
	 */
	private $table_name;

	/**
	 * Singleton instance
	 * @var	CountryBlockerDB
	 */
	private static $instance = null;

	/**
	 * Initialize the database handler
	 */
	private function __construct() {
		global $wpdb;
		$this->table_name = $wpdb->prefix . 'country_visitor_stats';
	}

	/**
	 * Get singleton instance
	 * @return	CountryBlockerDB
	 */
	public static function get_instance() {
		if (self::$instance === null) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Check if the required table exists
	 * @return	bool
	 */
	public function table_exists() {
		global $wpdb;
		
		return (bool)$wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(1) FROM information_schema.tables WHERE table_schema = %s AND table_name = %s",
			DB_NAME,
			$this->table_name
		));
	}

	/**
	 * Initialize the database table
	 * @return void
	 */
	public function initialize_table() {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();
		
		$sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
			country_code varchar(2) NOT NULL,
			total_visits int DEFAULT 1,
			blocked_visits int DEFAULT 0,
			first_visit datetime DEFAULT CURRENT_TIMESTAMP,
			last_visit datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (country_code)
		) $charset_collate;";
		
		require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
		dbDelta($sql);
		
		// Preload countries if table was just created
		if ($wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name}") == 0) {
			$csv_path = COUNTRY_BLOCKER_PATH . '/assets/country-preload.csv';
			$this->preload_visitor_stats($csv_path);
		}
	}

	/**
	 * Preload visitor statistics with initial country data
	 * 
	 * @param string $csv_path Path to the CSV file containing country data
	 * @return int Number of countries preloaded
	 */
	public function preload_visitor_stats($csv_path) {
		global $wpdb;
		
		// Verify file exists and is readable
		if (!file_exists($csv_path) || !is_readable($csv_path)) {
			return 0;
		}
		
		// Read CSV file
		$handle = fopen($csv_path, 'r');
		if ($handle === false) {
			return 0;
		}
		
		$count = 0;

		// Start transaction for data consistency
		$wpdb->query('START TRANSACTION');
		
		try {
			// Process each line
			while (($data = fgetcsv($handle)) !== false) {
				if (count($data) !== 2) {
					continue;							// Skip invalid rows
				}
				
				// Extract country name and code
				$country_name = trim($data[0], '"');	// Remove quotes if present
				$country_code = trim($data[1], '"');
				
				// Validate country code format (2 letters)
				if (strlen($country_code) !== 2) {
					continue;
				}
				
				// Only insert if country doesn't already exist
				$exists = $wpdb->get_var($wpdb->prepare(
					"SELECT 1 FROM {$this->table_name} WHERE country_code = %s",
					$country_code
				));
				
				if (!$exists) {
					// Insert with minimal initial visits
					$wpdb->insert(
						$this->table_name,
						array(
							'country_code' => $country_code,
							'total_visits' => 0,
							'blocked_visits' => 0,
							'first_visit' => NULL,
							'last_visit' => NULL
						),
						array('%s', '%d', '%d', '%s', '%s')
					);
					
					if ($wpdb->last_error === '') {
						$count++;
					}
				}
			}
			
			// Commit transaction if everything succeeded
			$wpdb->query('COMMIT');
			
		} catch (Exception $e) {
			// Rollback on any error
			$wpdb->query('ROLLBACK');
			$count = 0;
		}
		
		fclose($handle);
		return $count;
	}

	/**
	 * Update visit statistics for a country
	 * @param	string	$country_code	Two-letter country code
	 */
	public function update_visit_stats($country_code) {
		global $wpdb;
		
		$wpdb->query($wpdb->prepare(
			"INSERT INTO {$this->table_name} (country_code, total_visits, first_visit, last_visit) 
			VALUES (%s, 1, NOW(), NOW())
			ON DUPLICATE KEY UPDATE 
				total_visits = total_visits + 1,
				first_visit = COALESCE(first_visit, NOW()),
				last_visit = NOW()",
			$country_code
		));
	}

	/**
	 * Update blocked visit counter for a country
	 * @param	string	$country_code	Two-letter country code
	 */
	public function update_blocked_stats($country_code) {
		global $wpdb;
		
		$wpdb->query($wpdb->prepare(
			"UPDATE {$this->table_name} 
			SET blocked_visits = blocked_visits + 1 
			WHERE country_code = %s",
			$country_code
		));
	}

	/**
	 * Get visitor statistics
	 * @return	array	Array of visitor statistics by country
	 */
	public function get_visitor_stats() {
		global $wpdb;
		
		return $wpdb->get_results(
			"SELECT country_code, total_visits, blocked_visits, 
					first_visit, last_visit
			 FROM {$this->table_name} 
			 ORDER BY total_visits DESC"
		);
	}
}