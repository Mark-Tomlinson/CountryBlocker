jQuery(document).ready(function($) {
	// Initialize TableSorter (just for sorting)
	var $table = $('.wp-list-table').tablesorter({
		headers: {6: {sorter: false}},	// Disable sorting on checkbox column
		sortList: [[2,1]]				// Default sort by total visits descending
	});

	// Define filter states
	var filterStates = ['all', 'blocked', 'unblocked'];
	var currentState = 0;

	// Add state indicator checkbox to header
	var $headerInner = $('.wp-list-table thead tr th:last-child .tablesorter-header-inner');
	var $stateCheckbox = $('<input type="checkbox" onclick="return false;" disabled>');
	$headerInner.append($stateCheckbox);

	// Click handler for Block Country header
	$headerInner.click(function(e) {
		console.log('Block Country header inner clicked!');
		e.stopPropagation();
		
		if ($(e.target).is('input')) return;
		
		// Cycle through states
		currentState = (currentState + 1) % filterStates.length;
		var state = filterStates[currentState];
		console.log('Setting filter state:', state);

		// Update state indicator
		if (state === 'blocked') {
			$stateCheckbox.prop('indeterminate', false).prop('checked', true).prop('disabled', false);
		} else if (state === 'unblocked') {
			$stateCheckbox.prop('indeterminate', false).prop('checked', false).prop('disabled', false);
		} else {
			$stateCheckbox.prop('indeterminate', true).prop('disabled', true);
		}

		// Show all rows first
		$('.wp-list-table tbody tr').show();
		
		// Apply filter based on state
		if (state === 'blocked') {
			$('.wp-list-table tbody tr').filter(function() {
				return !$(this).find('input[type="checkbox"]').prop('checked');
			}).hide();
		} else if (state === 'unblocked') {
			$('.wp-list-table tbody tr').filter(function() {
				return $(this).find('input[type="checkbox"]').prop('checked');
			}).hide();
		}
	});
});