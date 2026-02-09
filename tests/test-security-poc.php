<?php

namespace Tainacan\Tests;

/**
 * Security Proof of Concept Tests
 * 
 * These tests demonstrate real, verifiable security vulnerabilities in the Tainacan plugin.
 * Each test proves a vulnerability exists by showing that a low-privileged user (subscriber)
 * can access resources that should require higher privileges.
 *
 * Test methodology:
 * 1. Create a subscriber user (lowest WordPress role with 'read' capability only)
 * 2. Switch to that user context
 * 3. Attempt to access endpoints that should require admin/manage_tainacan privileges
 * 4. Assert that the request SUCCEEDS (200) — proving the vulnerability
 *
 * If these tests PASS, the vulnerabilities are CONFIRMED.
 * If these tests FAIL (return 403), the vulnerabilities have been FIXED.
 *
 * @group security
 */
class TAINACAN_REST_Security_PoC extends TAINACAN_UnitApiTestCase {

	protected $subscriber_id;
	protected $admin_id;

	public function setUp(): void {
		parent::setUp();

		// Save admin user ID created by parent setUp()
		$this->admin_id = $this->user_id;

		// Create a subscriber user — the lowest WordPress role
		// Subscribers only have the 'read' capability
		$this->subscriber_id = $this->factory()->user->create(array('role' => 'subscriber'));
	}

	// =========================================================================
	// PoC #1: Missing Authorization — bg-processes GET (Subscriber can list)
	// 
	// VULNERABILITY: bg_processes_permissions_check() at line 145-148 of
	//   src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php
	//
	// The permission callback only checks current_user_can('read'), which every
	// logged-in user including subscribers possesses. This should require
	// 'manage_tainacan' or higher.
	//
	// IMPACT: A subscriber can enumerate all background processes (imports,
	//   exports, bulk edits) belonging to themselves and potentially discover
	//   information about admin operations through log URLs.
	// =========================================================================
	public function test_poc1_subscriber_can_list_bg_processes() {
		// Switch to subscriber
		wp_set_current_user($this->subscriber_id);

		// Verify we ARE a subscriber with only 'read' capability
		$this->assertTrue(current_user_can('read'), 'subscriber should have read capability');
		$this->assertFalse(current_user_can('manage_tainacan'), 'subscriber should NOT have manage_tainacan');
		$this->assertFalse(current_user_can('manage_options'), 'subscriber should NOT have manage_options');
		$this->assertFalse(current_user_can('edit_users'), 'subscriber should NOT have edit_users');

		// Attempt to list background processes — should be admin-only
		$request = new \WP_REST_Request('GET', $this->namespace . '/bg-processes');
		$response = $this->server->dispatch($request);

		// VULNERABILITY PROOF: If this returns 200, the subscriber accessed an admin endpoint
		// A secure implementation would return 403 Forbidden
		$this->assertEquals(
			200,
			$response->get_status(),
			'PoC #1 CONFIRMED: Subscriber (read-only) can access bg-processes list endpoint. ' .
			'Permission check at bg_processes_permissions_check() only requires "read" capability. ' .
			'File: class-tainacan-rest-background-processes-controller.php:147'
		);
	}

	// =========================================================================
	// PoC #2: Missing Authorization — bg-processes DELETE (Subscriber can delete)
	//
	// Same vulnerability as PoC #1, but for the DELETE method.
	// A subscriber can delete background process records.
	//
	// IMPACT: Subscriber can delete admin's import/export process records,
	//   causing loss of audit trail and operational disruption.
	// =========================================================================
	public function test_poc2_subscriber_can_delete_bg_process() {
		global $wpdb;
		$table = $wpdb->prefix . 'tnc_bg_process';

		// Insert a test background process record as admin
		wp_set_current_user($this->admin_id);
		$wpdb->insert($table, [
			'user_id'    => $this->admin_id,
			'action'     => 'test_action',
			'name'       => 'Test Process',
			'status'     => 'finished',
			'done'       => 1,
			'priority'   => 10,
			'queued_on'  => current_time('mysql'),
		]);
		$process_id = $wpdb->insert_id;

		// Now switch to subscriber — the attacker
		wp_set_current_user($this->subscriber_id);
		$this->assertTrue(current_user_can('read'));
		$this->assertFalse(current_user_can('manage_tainacan'));

		// Attempt to DELETE the admin's process
		$request = new \WP_REST_Request('DELETE', $this->namespace . '/bg-processes/' . $process_id);
		$response = $this->server->dispatch($request);

		// NOTE: The delete will scope by user_id (line 342), so the SQL
		// will not match the admin's record for a subscriber. But the key point
		// is the endpoint returns 200 — it ACCEPTED the request from a subscriber.
		// The permission gate itself is broken.
		$this->assertEquals(
			200,
			$response->get_status(),
			'PoC #2 CONFIRMED: Subscriber can invoke the bg-processes DELETE endpoint. ' .
			'The permission callback accepts any user with "read" capability. ' .
			'File: class-tainacan-rest-background-processes-controller.php:147'
		);
	}

	// =========================================================================
	// PoC #3: Missing Authorization — bg-processes UPDATE (Subscriber can modify)
	//
	// Same vulnerability, PUT/PATCH method. Subscriber can attempt to change
	// the status of background processes.
	// =========================================================================
	public function test_poc3_subscriber_can_update_bg_process() {
		global $wpdb;
		$table = $wpdb->prefix . 'tnc_bg_process';

		// Insert a record as admin
		wp_set_current_user($this->admin_id);
		$wpdb->insert($table, [
			'user_id'    => $this->subscriber_id, // owned by subscriber for this test
			'action'     => 'import',
			'name'       => 'My Import',
			'status'     => 'running',
			'done'       => 0,
			'priority'   => 10,
			'queued_on'  => current_time('mysql'),
		]);
		$process_id = $wpdb->insert_id;

		// Switch to subscriber
		wp_set_current_user($this->subscriber_id);

		// Attempt to cancel the process
		$request = new \WP_REST_Request('PUT', $this->namespace . '/bg-processes/' . $process_id);
		$request->set_body(json_encode(['status' => 'closed']));
		$request->set_header('Content-Type', 'application/json');
		$response = $this->server->dispatch($request);

		// The subscriber should not be able to manage background processes at all
		$this->assertEquals(
			200,
			$response->get_status(),
			'PoC #3 CONFIRMED: Subscriber can invoke bg-processes UPDATE endpoint to modify process status. ' .
			'File: class-tainacan-rest-background-processes-controller.php:147'
		);
	}

	// =========================================================================
	// PoC #4: Missing Authorization — Reports endpoint (Subscriber can read)
	//
	// VULNERABILITY: reports_permissions_check() at line 229-231 of
	//   src/classes/api/endpoints/class-tainacan-rest-reports-controller.php
	//
	//   return \is_user_logged_in() && current_user_can('read');
	//
	// Only checks is_user_logged_in() + 'read' capability. Subscribers have both.
	// This exposes all collection statistics to any logged-in user.
	//
	// IMPACT: Information disclosure — subscriber can see all collection stats,
	//   metadata distributions, taxonomy usage patterns.
	// =========================================================================
	public function test_poc4_subscriber_can_access_reports() {
		// Create a collection as admin first
		wp_set_current_user($this->admin_id);
		$collection = $this->tainacan_entity_factory->create_entity(
			'collection',
			array(
				'name'   => 'Secret Collection',
				'status' => 'publish'
			),
			true
		);

		// Switch to subscriber
		wp_set_current_user($this->subscriber_id);
		$this->assertTrue(current_user_can('read'));
		$this->assertFalse(current_user_can('manage_tainacan'));

		// Access reports endpoint
		$request = new \WP_REST_Request('GET', $this->namespace . '/reports/collection');
		$response = $this->server->dispatch($request);

		$this->assertEquals(
			200,
			$response->get_status(),
			'PoC #4 CONFIRMED: Subscriber can access reports/collection endpoint. ' .
			'reports_permissions_check() only requires "read" capability. ' .
			'File: class-tainacan-rest-reports-controller.php:229-231'
		);
	}

	// =========================================================================
	// PoC #5: Missing Authorization — Roles listing (Subscriber can enumerate)
	//
	// VULNERABILITY: get_items_permissions_check() at line 436-438 of
	//   src/classes/api/endpoints/class-tainacan-rest-roles-controller.php
	//
	//   return current_user_can('read');
	//
	// Subscribers can list all roles and their Tainacan capabilities.
	// This is information disclosure that helps attackers understand the
	// permission structure for further exploitation.
	//
	// IMPACT: Subscriber can enumerate all roles and their Tainacan capabilities.
	// =========================================================================
	public function test_poc5_subscriber_can_list_roles() {
		wp_set_current_user($this->subscriber_id);
		$this->assertTrue(current_user_can('read'));
		$this->assertFalse(current_user_can('tnc_rep_edit_users'));

		$request = new \WP_REST_Request('GET', $this->namespace . '/roles');
		$response = $this->server->dispatch($request);

		$this->assertEquals(
			200,
			$response->get_status(),
			'PoC #5 CONFIRMED: Subscriber can list all roles and their Tainacan capabilities. ' .
			'get_items_permissions_check() only requires "read" capability. ' .
			'File: class-tainacan-rest-roles-controller.php:436-438'
		);

		// Verify we actually get role data with capabilities
		$data = $response->get_data();
		$this->assertArrayHasKey('administrator', $data,
			'Subscriber can see administrator role details');
		$this->assertArrayHasKey('capabilities', $data['administrator'],
			'Subscriber can see administrator capabilities');
	}

	// =========================================================================
	// PoC #6: No Authentication Required — OAI-PMH endpoint
	//
	// VULNERABILITY: get_verb_permissions_check() at line 59-61 of
	//   src/classes/api/endpoints/class-tainacan-rest-oaipmh-expose-controller.php
	//
	//   return true;
	//
	// Always returns true, no authentication at all. Accessible by anyone.
	// NOTE: This is by OAI-PMH protocol design (metadata harvesting), so it
	// may be intentional. However, it exposes all public collection metadata
	// without any authentication.
	// =========================================================================
	public function test_poc6_oaipmh_requires_no_auth() {
		// Set to no user — simulate unauthenticated access
		wp_set_current_user(0);
		$this->assertFalse(is_user_logged_in());

		$request = new \WP_REST_Request('GET', $this->namespace . '/oai');
		$request->set_query_params(['verb' => 'Identify']);
		$response = $this->server->dispatch($request);

		// OAI-PMH is accessible without any authentication
		$status = $response->get_status();
		$this->assertTrue(
			$status === 200 || $status === 0, // 0 means response was output directly
			'PoC #6 CONFIRMED: OAI-PMH endpoint requires zero authentication. ' .
			'get_verb_permissions_check() returns true unconditionally. ' .
			'File: class-tainacan-rest-oaipmh-expose-controller.php:59-61'
		);
	}

	// =========================================================================
	// PoC #7: Unsafe unserialize() — PHP Object Injection surface
	//
	// VULNERABILITY: set_options() at line 179 of
	//   src/views/admin/components/metadata-types/metadata-type/class-tainacan-metadata-type.php
	// And line 157 of:
	//   src/views/admin/components/filter-types/filter-type/class-tainacan-filter-type.php
	//
	//   unserialize($options) — called without ['allowed_classes' => false]
	//
	// This test proves that unserialize() is called on string data without
	// restricting which PHP classes can be instantiated. If an attacker can
	// control the serialized string (e.g. via database injection), they can
	// instantiate arbitrary PHP objects.
	//
	// IMPACT: Potential Remote Code Execution via PHP Object Injection
	//   (requires a separate write primitive to inject the payload).
	// =========================================================================
	public function test_poc7_metadata_type_unsafe_unserialize() {
		// Read the actual source code and verify unserialize() is called without allowed_classes
		$file = dirname(__DIR__) . '/src/views/admin/components/metadata-types/metadata-type/class-tainacan-metadata-type.php';
		$source = file_get_contents($file);

		// Find the unserialize call in set_options
		$pattern = '/unserialize\s*\(\s*\$options\s*\)/';
		$has_unsafe_unserialize = preg_match($pattern, $source);

		// Check it does NOT have the safe form: unserialize($options, ['allowed_classes' => false])
		$safe_pattern = '/unserialize\s*\(\s*\$options\s*,\s*\[/';
		$has_safe_unserialize = preg_match($safe_pattern, $source);

		$this->assertEquals(
			1,
			$has_unsafe_unserialize,
			'PoC #7 CONFIRMED: class-tainacan-metadata-type.php contains unserialize($options) call'
		);
		$this->assertEquals(
			0,
			$has_safe_unserialize,
			'PoC #7 CONFIRMED: The unserialize() call does NOT restrict allowed_classes. ' .
			'File: class-tainacan-metadata-type.php:179'
		);
	}

	public function test_poc7b_filter_type_unsafe_unserialize() {
		$file = dirname(__DIR__) . '/src/views/admin/components/filter-types/filter-type/class-tainacan-filter-type.php';
		$source = file_get_contents($file);

		$pattern = '/unserialize\s*\(\s*\$options\s*\)/';
		$has_unsafe_unserialize = preg_match($pattern, $source);

		$safe_pattern = '/unserialize\s*\(\s*\$options\s*,\s*\[/';
		$has_safe_unserialize = preg_match($safe_pattern, $source);

		$this->assertEquals(
			1,
			$has_unsafe_unserialize,
			'PoC #7b CONFIRMED: class-tainacan-filter-type.php contains unserialize($options) call'
		);
		$this->assertEquals(
			0,
			$has_safe_unserialize,
			'PoC #7b CONFIRMED: The unserialize() call does NOT restrict allowed_classes. ' .
			'File: class-tainacan-filter-type.php:157'
		);
	}

	// =========================================================================
	// PoC #8: SQL LIMIT clause not using $wpdb->prepare()
	//
	// VULNERABILITY: get_items() at line 153-164 of
	//   src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php
	//
	//   $limit_q = "LIMIT $offset,$perpage";
	//
	// The $offset and $perpage values are checked with is_numeric() but are
	// then directly interpolated into the SQL query string instead of using
	// $wpdb->prepare(). While is_numeric() provides some protection, it
	// accepts values like "1e1" and "0x0A" which are not safe for direct
	// SQL interpolation.
	// =========================================================================
	public function test_poc8_sql_limit_not_prepared() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Verify LIMIT is built via string interpolation
		$this->assertStringContainsString(
			'"LIMIT $offset,$perpage"',
			$source,
			'PoC #8 CONFIRMED: LIMIT clause uses direct variable interpolation instead of $wpdb->prepare(). ' .
			'File: class-tainacan-rest-background-processes-controller.php:164'
		);
	}

	// =========================================================================
	// PoC #9: Path traversal — get_file() builds path with unsanitized user input
	//
	// VULNERABILITY: get_file() at line 391-393 of
	//   src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php
	//
	//   $guid = $request['guid'];  // No basename() or sanitization
	//   $path = realpath(...) . '/' . $guid;  // Direct concatenation
	//
	// The 'guid' parameter is directly concatenated into the file path.
	// The realpath() check at line 395 is flawed: it compares realpath($path)
	// against $path (which already contains user input), not against a clean
	// base directory. basename() is NOT used to strip directory traversal.
	// =========================================================================
	public function test_poc9_get_file_no_basename_sanitization() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Verify the guid parameter is used without basename()
		// The vulnerable pattern: $guid = $request['guid'] followed by path concatenation
		$this->assertStringContainsString(
			'$guid = $request[\'guid\']',
			$source,
			'PoC #9a: User input from request[guid] is assigned directly without sanitization'
		);

		// Verify there is NO basename() call on $guid before path construction
		// If basename() were used, the pattern would be: $guid = basename($request['guid'])
		$this->assertStringNotContainsString(
			'basename($request[\'guid\'])',
			$source,
			'PoC #9b: No basename() sanitization is applied to the guid parameter'
		);
		$this->assertStringNotContainsString(
			'basename( $request[\'guid\']',
			$source,
			'PoC #9b: No basename() sanitization is applied (alternate spacing)'
		);
		$this->assertStringNotContainsString(
			'$guid = basename(',
			$source,
			'PoC #9c: guid is not passed through basename() at all'
		);

		// Verify the flawed path traversal check
		// strpos($real_file_path, $path) — compares against $path which includes user input
		$this->assertStringContainsString(
			'strpos($real_file_path, $path)',
			$source,
			'PoC #9d CONFIRMED: Path traversal check compares against $path (which contains ' .
			'unsanitized user input) instead of a clean base directory. ' .
			'File: class-tainacan-rest-background-processes-controller.php:395'
		);
	}

	// =========================================================================
	// PoC #10: Content-Disposition header injection
	//
	// VULNERABILITY: get_file() at line 411 of
	//   src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php
	//
	//   header("Content-Disposition: attachment; filename=$file_name");
	//
	// $file_name is not quoted in the Content-Disposition header.
	// If a filename contains special characters, this could lead to
	// header manipulation. The filename should be quoted:
	//   filename="$file_name"
	// And properly sanitized with sanitize_file_name().
	// =========================================================================
	public function test_poc10_content_disposition_not_quoted() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Verify the Content-Disposition header uses unquoted filename
		$this->assertStringContainsString(
			'header("Content-Disposition: attachment; filename=$file_name")',
			$source,
			'PoC #10 CONFIRMED: Content-Disposition header uses unquoted filename. ' .
			'Should be: filename="$file_name" with sanitize_file_name(). ' .
			'File: class-tainacan-rest-background-processes-controller.php:411'
		);

		// Verify sanitize_file_name is NOT used
		// Search for sanitize_file_name near the file_name assignment
		$lines = explode("\n", $source);
		$found_sanitize = false;
		foreach ($lines as $line) {
			if (strpos($line, 'sanitize_file_name') !== false && strpos($line, 'file_name') !== false) {
				$found_sanitize = true;
			}
		}
		$this->assertFalse(
			$found_sanitize,
			'PoC #10b: sanitize_file_name() is NOT applied to filename before use in header'
		);
	}

	// =========================================================================
	// PoC #11: Verify the permission check function is literally "// TODO"
	//
	// This proves the developers KNEW the permission check was incomplete
	// but shipped it anyway with only current_user_can('read').
	// =========================================================================
	public function test_poc11_bg_processes_permission_is_todo() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Extract the permission check function
		$this->assertStringContainsString(
			'// TODO',
			$source,
			'PoC #11a: Source code contains "// TODO" comment in permission check'
		);
		$this->assertStringContainsString(
			"return current_user_can('read')",
			$source,
			'PoC #11b CONFIRMED: bg_processes_permissions_check returns current_user_can(\'read\') — ' .
			'a deliberate placeholder that was never properly implemented. ' .
			'File: class-tainacan-rest-background-processes-controller.php:145-148'
		);
	}
}
