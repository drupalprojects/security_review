<?php

/**
 * @file
 * Contains \Drupal\security_review\Tests\CheckWebTest.
 */

namespace Drupal\security_review\Tests;

use Drupal\simpletest\WebTestBase;

/**
 * Contains tests for Check that don't suffice with KernelTestBase.
 *
 * @group security_review
 */
class CheckWebTest extends WebTestBase {

  /**
   * Modules to enable.
   *
   * @var array
   */
  public static $modules = array('security_review');

  /**
   * The security checks defined by Security Review.
   *
   * @var \Drupal\security_review\Check[]
   */
  protected $checks;

  /**
   * The test user.
   *
   * @var \Drupal\user\Entity\User
   */
  protected $user;

  /**
   * Sets up the testing environment, logs the user in, populates $check.
   */
  protected function setUp() {
    parent::setUp();

    // Login.
    $this->user = $this->drupalCreateUser(
      array(
        'run security checks',
        'access security review list',
        'access administration pages',
        'administer site configuration',
      )
    );
    $this->drupalLogin($this->user);

    // Get checks.
    $this->checks = security_review_security_review_checks();
  }

  /**
   * Tests Check::skip().
   *
   * Checks whether skip() marks the check as skipped, and checks the
   * skippedBy() value.
   */
  public function testSkipCheck() {
    foreach ($this->checks as $check) {
      $check->skip();

      $is_skipped = $check->isSkipped();
      $skipped_by = $check->skippedBy();

      $this->assertTrue($is_skipped, $check->getTitle() . ' skipped.');
      $this->assertEqual($this->user->id(), $skipped_by->id(), 'Skipped by ' . $skipped_by->label());
    }
  }

}
