<?php

/**
 * @file
 * Contains \Drupal\security_review\Checks\TemporaryFiles.
 */

namespace Drupal\security_review\Checks;

use Drupal\security_review\Check;
use Drupal\security_review\CheckResult;

/**
 * Check for sensitive temporary files like settings.php~.
 */
class TemporaryFiles extends Check {

  /**
   * {@inheritdoc}
   */
  public function getNamespace() {
    return 'Security Review';
  }

  /**
   * {@inheritdoc}
   */
  public function getTitle() {
    return 'Temporary files';
  }

  /**
   * {@inheritdoc}
   */
  public function run() {
    $result = CheckResult::SUCCESS;
    $findings = array();

    $files = array();
    $sitePath = DRUPAL_ROOT . '/' . \Drupal::service('kernel')->getSitePath() . '/';
    $dir = scandir($sitePath);
    foreach ($dir as $file) {
      // Set full path to only files.
      if (!is_dir($file)) {
        $files[] = $sitePath . $file;
      }
    }

    \Drupal::moduleHandler()->alter('security_review_temporary_files', $files);
    foreach ($files as $path) {
      $matches = array();
      if (file_exists($path) && preg_match('/.*(~|\.sw[op]|\.bak|\.orig|\.save)$/', $path, $matches) !== FALSE && !empty($matches)) {
        $result = CheckResult::FAIL;
        $findings[] = $path;
      }
    }

    return $this->createResult($result, $findings);
  }

  /**
   * {@inheritdoc}
   */
  public function help() {
    $paragraphs = array();
    $paragraphs[] = "Some file editors create temporary copies of a file that can be left on the file system. A copy of a sensitive file like Drupal's settings.php may be readable by a malicious user who could use that information to further attack a site.";

    return array(
      '#theme' => 'check_help',
      '#title' => 'Sensitive temporary files',
      '#paragraphs' => $paragraphs
    );
  }

  /**
   * {@inheritdoc}
   */
  public function evaluate(CheckResult $result) {
    $findings = $result->findings();
    if (empty($findings)) {
      return array();
    }

    $paragraphs = array();
    $paragraphs[] = "The following are extraneous files in your Drupal installation that can probably be removed. You should confirm you have saved any of your work in the original files prior to removing these.";

    return array(
      '#theme' => 'check_evaluation',
      '#paragraphs' => $paragraphs,
      '#items' => $findings
    );
  }

  /**
   * {@inheritdoc}
   */
  public function evaluatePlain(CheckResult $result) {
    $findings = $result->findings();
    if (empty($findings)) {
      return '';
    }

    $output = '';
    foreach ($findings as $file) {
      $output .= "\t" . $file . "\n";
    }

    return $output;
  }

  /**
   * {@inheritdoc}
   */
  public function getMessage($resultConst) {
    switch ($resultConst) {
      case CheckResult::SUCCESS:
        return 'No sensitive temporary files were found.';
      case CheckResult::FAIL:
        return 'Sensitive temporary files were found on your files system.';
      default:
        return 'Unexpected result.';
    }
  }

}
