<?php

/**
 * @file
 * Contains \Drupal\security_review\CheckSettingsInterface.
 */

namespace Drupal\security_review;

/**
 * Defines an interface for accessing check-specific settings and creating forms
 * that can alter these settings.
 */
interface CheckSettingsInterface {
  /**
   * Gets a check-specific setting value identified by $key.
   *
   * @param $key
   *   The key.
   *
   * @return mixed
   *   The value of the stored setting.
   */
  public function get($key);

  /**
   * Sets a check-specific setting value identified by $key.
   *
   * @param $key
   *   The key.
   * @param $value
   *   The new value.
   *
   * @return CheckSettingsInterface
   *   Returns itself.
   */
  public function set($key, $value);

  /**
   * Form constructor.
   *
   * @return array
   *   The form structure.
   */
  public function buildForm();

  /**
   * Form validation handler.
   *
   * @param array $form
   *   An associative array containing the structure of the form.
   * @param array $values
   *   The current values of the form.
   */
  public function validateForm(array &$form, $values);

  /**
   * Form submission handler.
   *
   * @param array $form
   *   An associative array containing the structure of the form.
   * @param array $values
   *   The current values of the form.
   */
  public function submitForm(array &$form, $values);
}
