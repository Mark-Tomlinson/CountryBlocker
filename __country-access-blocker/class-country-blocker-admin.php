<?php
/**
 * Country Access Blocker Admin Interface
 *
 * Handles all WordPress admin functionality for the Country Access Blocker plugin.
 * Provides the settings page, country blocking controls, and statistics display.
 *
 * @package		WordPress
 * @subpackage	Security\CountryBlocker
 * @since		1.10
 */

if (!defined('ABSPATH')) exit;

class CountryBlockerAdmin {
	/**
	 * Array of country codes and country names
	 * @var	array
	 */
	private $countries = array();

	/**
	 * Initialize the admin interface and hooks
	 */
	public function __construct() {
		// Add admin menu and register settings
		add_action('admin_menu', array($this, 'add_admin_menu'));
		add_action('admin_init', array($this, 'register_settings'));
		
		// Add scripts and styles for admin page
		add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));

		// Initialize options if they don't exist
		if (get_option(COUNTRY_BLOCKER_OPTIONS['blocked_countries']) === false) {
			add_option(COUNTRY_BLOCKER_OPTIONS['blocked_countries'], array());
		}
	}

	/**
	 * Enqueues required scripts and styles for admin page
	 * @param   string  $hook   Current admin page hook
	 */
	public function enqueue_admin_scripts($hook) {
		if ($hook !== 'toplevel_page_country-blocker') {
			return;
		}

		// Enqueue TableSorter core (only needed for sorting now)
		wp_enqueue_script(
			'tablesorter',
			'https://cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.32.0/js/jquery.tablesorter.min.js',
			array('jquery'),
			'2.32.0',
			true
		);

		// Enqueue our custom script
		wp_enqueue_script(
			'country-blocker-admin',
			plugins_url(COUNTRY_BLOCKER_FOLDER . '/js/admin.js', dirname(__FILE__)),
			array('tablesorter'),
			COUNTRY_BLOCKER_VERSION,
			true
		);
	}

	/**
	 * Adds the plugin's menu item to the WordPress admin menu
	 */
	public function add_admin_menu() {
		add_menu_page(
			'Country Blocker Settings',
			'Country Blocker',
			'manage_options',
			'country-blocker',
			array($this, 'render_admin_page'),
			'dashicons-admin-site'
		);
	}

	/**
	 * Registers plugin settings with WordPress
	 */
	public function register_settings() {
		register_setting(
			'country_blocker_options',
			COUNTRY_BLOCKER_OPTIONS['blocked_countries'],
			array(
				'type' => 'array',
				'sanitize_callback' => array($this, 'sanitize_blocked_countries')
			)
		);
	}

	/**
	 * Loads country data from CSV file into memory
	 */
	private function load_country_data() {
		$csv_file = COUNTRY_BLOCKER_PATH . '/assets/country-access-blocker-countries.csv';
		if (file_exists($csv_file)) {
			$handle = fopen($csv_file, 'r');
			if ($handle !== false) {
				while (($data = fgetcsv($handle)) !== false) {
					if (isset($data[0], $data[1])) {
						$this->countries[$data[0]] = $data[1];
					}
				}
				fclose($handle);
			}
		}
	}

	/**
	 * Gets the full country name for a country code
	 * @param	string	$code	Two-letter country code
	 * @return	string			Full country name or original code if not found
	 */
	private function get_country_name($code) {
		return isset($this->countries[$code]) ? $this->countries[$code] : $code;
	}

	/**
	 * Sanitizes the list of blocked countries
	 * @param	mixed	$input	Input value to sanitize
	 * @return	array			Sanitized array of country codes
	 */
	public function sanitize_blocked_countries($input) {
		if (empty($input)) {
			return array();
		}
		
		if (is_string($input)) {
			$input = explode(',', $input);
		}
		
		$sanitized = array();
		foreach ((array)$input as $country_code) {
			if (is_string($country_code) && strlen($country_code) === 2) {
				$sanitized[] = strtoupper(sanitize_text_field($country_code));
			}
		}
		
		return $sanitized;
	}

	/**
	 * Renders the plugin's admin page
	 */
	public function render_admin_page() {
		// Load country data only when needed
		$this->load_country_data();
		
		// Get visitor stats from the database handler
		$visitor_stats = country_blocker_db()->get_visitor_stats();
		$blocked_countries = get_option(COUNTRY_BLOCKER_OPTIONS['blocked_countries'], array());
		$admin_country = get_option(COUNTRY_BLOCKER_OPTIONS['admin_country']);
		
		?>
		<div class="wrap">
			<h1>Country Blocker Settings</h1>
			<style>
				.widefat tr.country-blocked td { color: #600030 !important; }
				.widefat tr.country-unblocked td { color: #006030 !important; }
				th.tablesorter-headerAsc, th.tablesorter-headerDesc { background: #f8f8f8; }
				th.tablesorter-headerUnSorted:not(:last-child) .tablesorter-header-inner:after { content: " ↕"; }
				th.tablesorter-headerAsc .tablesorter-header-inner:after { content: " ↑"; }
				th.tablesorter-headerDesc .tablesorter-header-inner:after { content: " ↓"; }
			</style>
			<?php if ($admin_country): ?>
			<div class="notice notice-info">
				<p>Your country (<?php echo esc_html($this->get_country_name($admin_country)); ?> - <?php echo esc_html($admin_country); ?>) is automatically protected and cannot be blocked.</p>
			</div>
			<?php endif; ?>

			<form method="post" action="options.php">
				<?php submit_button('Save Changes'); ?>
				<?php settings_fields('country_blocker_options'); ?>
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<th scope="col">Country</th>
							<th scope="col">Code</th>
							<th scope="col">Total Visits</th>
							<th scope="col">Blocked Visits</th>
							<th scope="col">First Visit</th>
							<th scope="col">Last Visit</th>
							<th scope="col">Block Country</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ($visitor_stats as $stat): 
							$row_class = in_array($stat->country_code, $blocked_countries) ? 
									'country-blocked' : 'country-unblocked';
						?>
						<tr class="<?php echo esc_attr($row_class); ?>">
							<td><?php echo esc_html($this->get_country_name($stat->country_code)); ?></td>
							<td><?php echo esc_html($stat->country_code); ?></td>
							<td data-sort-value="<?php echo esc_attr($stat->total_visits); ?>">
								<?php echo number_format($stat->total_visits); ?>
							</td>
							<td data-sort-value="<?php echo esc_attr($stat->blocked_visits); ?>">
								<?php echo number_format($stat->blocked_visits); ?>
							</td>
							<td data-sort-value="<?php echo esc_attr($stat->first_visit ? strtotime($stat->first_visit) : 0); ?>">
								<?php echo $stat->first_visit ? esc_html($stat->first_visit) : 'Never'; ?>
							</td>
							<td data-sort-value="<?php echo esc_attr($stat->last_visit ? strtotime($stat->last_visit) : 0); ?>">
								<?php echo $stat->last_visit ? esc_html($stat->last_visit) : 'Never'; ?>
							</td>							<td>
							<?php if ($stat->country_code === $admin_country) { ?>
								<span class="dashicons dashicons-lock"></span>
							<?php } else { ?>
								<input type="checkbox" 
									name="<?php echo esc_attr(COUNTRY_BLOCKER_OPTIONS['blocked_countries']); ?>[]"
									value="<?php echo esc_attr($stat->country_code); ?>"
									<?php checked(in_array($stat->country_code, $blocked_countries)); ?>>
							<?php }; ?>
							</td>
						</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php submit_button('Save Changes'); ?>
			</form>
		</div>
		<?php
	}
}