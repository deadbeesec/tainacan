<?php

namespace Tainacan\Tests;

/**
 * Security Fix Verification Tests
 *
 * These tests verify that the Missing Authorization vulnerability in the
 * bg-processes controller has been fixed, and that other security hardening
 * changes are properly applied.
 *
 * Test methodology:
 * 1. Create a subscriber user (lowest WordPress role with 'read' capability only)
 * 2. Switch to that user context
 * 3. Attempt to access endpoints that require manage_tainacan privilege
 * 4. Assert that the request is REJECTED (403) — proving the fix works
 * 5. Verify admin users can still access the endpoints (200)
 *
 * @group security
 */
class TAINACAN_REST_Security_Fix_Verification extends TAINACAN_UnitApiTestCase {

	protected $subscriber_id;
	protected $admin_id;

	public function setUp(): void {
		parent::setUp();

		// Save admin user ID created by parent setUp()
		$this->admin_id = $this->user_id;

		// Create a subscriber user — the lowest WordPress role
		$this->subscriber_id = $this->factory()->user->create(array('role' => 'subscriber'));
	}

	// =========================================================================
	// Test 1: Subscriber is BLOCKED from bg-processes GET
	//
	// Verifies the fix to bg_processes_permissions_check() which now requires
	// 'manage_tainacan' instead of 'read'.
	// =========================================================================
	public function test_subscriber_blocked_from_bg_processes_list() {
		wp_set_current_user($this->subscriber_id);

		$this->assertTrue(current_user_can('read'), 'subscriber should have read capability');
		$this->assertFalse(current_user_can('manage_tainacan'), 'subscriber should NOT have manage_tainacan');

		$request = new \WP_REST_Request('GET', $this->namespace . '/bg-processes');
		$response = $this->server->dispatch($request);

		$this->assertEquals(
			403,
			$response->get_status(),
			'Subscriber should be blocked (403) from bg-processes list endpoint. ' .
			'Fix: bg_processes_permissions_check() now requires manage_tainacan.'
		);
	}

	// =========================================================================
	// Test 2: Admin can still access bg-processes GET
	// =========================================================================
	public function test_admin_can_access_bg_processes_list() {
		wp_set_current_user($this->admin_id);

		$this->assertTrue(current_user_can('manage_tainacan'), 'admin should have manage_tainacan');

		$request = new \WP_REST_Request('GET', $this->namespace . '/bg-processes');
		$response = $this->server->dispatch($request);

		$this->assertEquals(
			200,
			$response->get_status(),
			'Admin should still be able to access bg-processes list endpoint (200).'
		);
	}

	// =========================================================================
	// Test 3: Subscriber is BLOCKED from bg-processes DELETE
	// =========================================================================
	public function test_subscriber_blocked_from_bg_processes_delete() {
		wp_set_current_user($this->subscriber_id);

		$request = new \WP_REST_Request('DELETE', $this->namespace . '/bg-processes/1');
		$response = $this->server->dispatch($request);

		$this->assertEquals(
			403,
			$response->get_status(),
			'Subscriber should be blocked (403) from bg-processes DELETE endpoint.'
		);
	}

	// =========================================================================
	// Test 4: Subscriber is BLOCKED from bg-processes UPDATE
	// =========================================================================
	public function test_subscriber_blocked_from_bg_processes_update() {
		wp_set_current_user($this->subscriber_id);

		$request = new \WP_REST_Request('PUT', $this->namespace . '/bg-processes/1');
		$request->set_body(json_encode(['status' => 'closed']));
		$request->set_header('Content-Type', 'application/json');
		$response = $this->server->dispatch($request);

		$this->assertEquals(
			403,
			$response->get_status(),
			'Subscriber should be blocked (403) from bg-processes UPDATE endpoint.'
		);
	}

	// =========================================================================
	// Test 5: Subscriber is BLOCKED from bg-processes file download
	// =========================================================================
	public function test_subscriber_blocked_from_bg_processes_file() {
		wp_set_current_user($this->subscriber_id);

		$request = new \WP_REST_Request('GET', $this->namespace . '/bg-processes/file');
		$request->set_query_params(['guid' => 'test.log']);
		$response = $this->server->dispatch($request);

		$this->assertEquals(
			403,
			$response->get_status(),
			'Subscriber should be blocked (403) from bg-processes file endpoint.'
		);
	}

	// =========================================================================
	// Test 6: Unauthenticated user is BLOCKED from all bg-processes endpoints
	// =========================================================================
	public function test_unauthenticated_blocked_from_bg_processes() {
		wp_set_current_user(0);

		$request = new \WP_REST_Request('GET', $this->namespace . '/bg-processes');
		$response = $this->server->dispatch($request);

		$this->assertEquals(
			401,
			$response->get_status(),
			'Unauthenticated user should be blocked (401) from bg-processes.'
		);
	}

	// =========================================================================
	// Test 7: Verify permission check no longer contains "// TODO" marker
	// =========================================================================
	public function test_permission_check_no_longer_todo() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Extract lines around the permission check function
		$lines = explode("\n", $source);
		$in_function = false;
		$function_body = '';
		foreach ($lines as $line) {
			if (strpos($line, 'function  bg_processes_permissions_check') !== false) {
				$in_function = true;
			}
			if ($in_function) {
				$function_body .= $line . "\n";
				if (strpos($line, '}') !== false && $in_function) {
					break;
				}
			}
		}

		$this->assertStringNotContainsString(
			'// TODO',
			$function_body,
			'Permission check function should no longer contain "// TODO" placeholder'
		);
		$this->assertStringContainsString(
			"manage_tainacan",
			$function_body,
			'Permission check should require manage_tainacan capability'
		);
		$this->assertStringNotContainsString(
			"return current_user_can('read')",
			$function_body,
			'Permission check should no longer use weak "read" capability'
		);
	}

	// =========================================================================
	// Test 8: Verify SQL LIMIT uses $wpdb->prepare() 
	// =========================================================================
	public function test_sql_limit_uses_prepare() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Verify the old vulnerable pattern is gone
		$this->assertStringNotContainsString(
			'"LIMIT $offset,$perpage"',
			$source,
			'SQL LIMIT should no longer use direct variable interpolation'
		);

		// Verify the safe pattern is present
		$this->assertStringContainsString(
			'$wpdb->prepare("LIMIT %d, %d"',
			$source,
			'SQL LIMIT should use $wpdb->prepare() with %d placeholders'
		);
	}

	// =========================================================================
	// Test 9: Verify get_file() uses basename() on guid parameter
	// =========================================================================
	public function test_get_file_uses_basename() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Verify basename() is applied to the guid parameter
		$this->assertStringContainsString(
			"basename(\$request['guid'])",
			$source,
			'get_file() should apply basename() to sanitize the guid parameter'
		);

		// Verify the old vulnerable pattern is gone
		$this->assertStringNotContainsString(
			"\$guid = \$request['guid'];\n",
			$source,
			'guid should not be assigned directly from request without basename()'
		);
	}

	// =========================================================================
	// Test 10: Verify path traversal check uses base directory comparison
	// =========================================================================
	public function test_path_traversal_check_uses_base_dir() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Verify the path check compares against $base_dir, not $path
		$this->assertStringContainsString(
			'strpos($real_file_path, $base_dir',
			$source,
			'Path traversal check should compare against the base directory, not the user-influenced path'
		);
	}

	// =========================================================================
	// Test 11: Verify Content-Disposition uses quoted filename
	// =========================================================================
	public function test_content_disposition_uses_quoted_filename() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Verify filename is quoted
		$this->assertStringContainsString(
			'filename="',
			$source,
			'Content-Disposition header should use quoted filename'
		);

		// Verify sanitize_file_name is used
		$this->assertStringContainsString(
			'sanitize_file_name',
			$source,
			'sanitize_file_name() should be applied to the filename'
		);
	}

	// =========================================================================
	// Test 12: Verify get_file() permission check uses manage_tainacan
	// =========================================================================
	public function test_get_file_uses_manage_tainacan() {
		$file = dirname(__DIR__) . '/src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php';
		$source = file_get_contents($file);

		// Find the get_file function and check its internal permission check
		$pattern = "/function get_file.*?current_user_can\('([^']+)'\)/s";
		preg_match($pattern, $source, $matches);

		$this->assertNotEmpty($matches, 'get_file should contain a current_user_can check');
		$this->assertEquals(
			'manage_tainacan',
			$matches[1],
			'get_file() internal permission check should require manage_tainacan, not read'
		);
	}
}
