<?php

/**
 * @file
 * Contains \Drupal\security_review\Checks\FilePermissions.
 */

namespace Drupal\security_review\Checks;

use Drupal;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\PublicStream;
use Drupal\Core\Url;
use Drupal\security_review\Check;
use Drupal\security_review\CheckResult;
use Drupal\security_review\Security;
use Drupal\security_review\SecurityReview;

/**
 * Check that files aren't writeable by the server.
 */
class FilePermissions extends Check {

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
    return 'File permissions';
  }

  /**
   * {@inheritdoc}
   */
  public function getMachineTitle() {
    return 'file_perms';
  }

  /**
   * {@inheritdoc}
   */
  public function storesFindings() {
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function run($cli = FALSE) {
    $result = CheckResult::SUCCESS;

    $file_list = $this->getFileList('.');
    $writable = Security::findWritableFiles($file_list, $cli);

    // Try creating or appending files.
    // Assume it doesn't work.
    $create_status = FALSE;
    $append_status = FALSE;

    if (!$cli) {
      $append_message = t("Your web server should not be able to write to your modules directory. This is a security vulnerable. Consult the Security Review file permissions check help for mitigation steps.");
      $directory = Drupal::moduleHandler()
        ->getModule('security_review')
        ->getPath();

      // Write a file with the timestamp.
      $file = './' . $directory . '/file_write_test.' . date('Ymdhis');
      if ($file_create = @fopen($file, 'w')) {
        $create_status = fwrite($file_create, date('Ymdhis') . ' - ' . $append_message . "\n");
        fclose($file_create);
      }

      // Try to append to our IGNOREME file.
      $file = './' . $directory . '/IGNOREME.txt';
      if ($file_append = @fopen($file, 'a')) {
        $append_status = fwrite($file_append, date('Ymdhis') . ' - ' . $append_message . "\n");
        fclose($file_append);
      }
    }

    if (!empty($writable) || $create_status || $append_status) {
      $result = CheckResult::FAIL;
    }

    return $this->createResult($result, $writable);
  }

  /**
   * {@inheritdoc}
   */
  public function runCli() {
    if (!SecurityReview::isServerPosix()) {
      return $this->createResult(CheckResult::INFO);
    }

    return $this->run(TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function help() {
    $paragraphs = array();
    $paragraphs[] = "It is dangerous to allow the web server to write to files inside the document root of your server. Doing so could allow Drupal to write files that could then be executed. An attacker might use such a vulnerability to take control of your site. An exception is the Drupal files, private files, and temporary directories which Drupal needs permission to write to in order to provide features like file attachments.";
    $paragraphs[] = "In addition to inspecting existing directories, this test attempts to create and write to your file system. Look in your security_review module directory on the server for files named file_write_test.YYYYMMDDHHMMSS and for a file called IGNOREME.txt which gets a timestamp appended to it if it is writeable.";
    $paragraphs[] = Drupal::l(t('Read more about file system permissions in the handbooks.'), Url::fromUri('http://drupal.org/node/244924'));

    return array(
      '#theme' => 'check_help',
      '#title' => 'Web server file system permissions',
      '#paragraphs' => $paragraphs,
    );
  }

  /**
   * {@inheritdoc}
   */
  public function evaluate(CheckResult $result) {
    if ($result->result() == CheckResult::SUCCESS) {
      return array();
    }

    $paragraphs = array();
    $paragraphs[] = t(
      '<p>The following files and directories appear to be writeable by your web server. In most cases you can fix this by simply altering the file permissions or ownership. If you have command-line access to your host try running "chmod 644 [file path]" where [file path] is one of the following paths (relative to your webroot). For more information consult the !link.</p>',
      array('!link' => Drupal::l(t('Drupal.org handbooks on file permissions'), Url::fromUri('http://drupal.org/node/244924')))
    );

    return array(
      '#theme' => 'check_evaluation',
      '#paragraphs' => $paragraphs,
      '#items' => $result->findings(),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function evaluatePlain(CheckResult $result) {
    if ($result->result() == CheckResult::SUCCESS) {
      return '';
    }

    $output = "Writable files:\n";
    foreach ($result->findings() as $file) {
      $output .= "\t" . $file . "\n";
    }

    return $output;
  }

  /**
   * {@inheritdoc}
   */
  public function getMessage($result_const) {
    switch ($result_const) {
      case CheckResult::SUCCESS:
        return 'Drupal installation files and directories (except required) are not writable by the server.';

      case CheckResult::FAIL:
        return 'Some files and directories in your install are writable by the server.';

      case CheckResult::INFO:
        return 'The test cannot be run on this system.';

      default:
        return 'Unexpected result.';
    }
  }

  /**
   * Scans a directory recursively and returns the files and directories inside.
   *
   * @param string $directory
   *   The directory to scan.
   * @param string[] $parsed
   *   Array of already parsed real paths.
   * @param string[] $ignore
   *   Array of file names to ignore.
   *
   * @return string[]
   *   The items found.
   */
  protected function getFileList($directory, array &$parsed = NULL, array &$ignore = NULL) {
    // Initialize $parsed and $ignore arrays.
    if ($parsed === NULL) {
      $parsed = array(realpath($directory));
    }
    if ($ignore === NULL) {
      $ignore = $this->getIgnoreList();
    }

    // Start scanning.
    $items = array();
    if ($handle = opendir($directory)) {
      while (($file = readdir($handle)) !== FALSE) {
        // Don't check hidden files or ones we said to ignore.
        $path = $directory . "/" . $file;
        if ($file[0] != "." && !in_array($file, $ignore) && !in_array(realpath($path), $ignore)) {
          if (is_dir($path) && !in_array(realpath($path), $parsed)) {
            $parsed[] = realpath($path);
            $items = array_merge($items, $this->getFileList($path, $parsed, $ignore));
          }
          $items[] = preg_replace("/\/\//si", "/", $path);
        }
      }
      closedir($handle);
    }

    return $items;
  }

  /**
   * Returns an array of relative and canonical paths to ignore.
   *
   * @return string[]
   *   List of relative and canonical file paths to ignore.
   */
  protected function getIgnoreList() {
    $file_path = PublicStream::basePath();
    $ignore = array('..', 'CVS', '.git', '.svn', '.bzr', realpath($file_path));

    // Add temporary files directory if it's set.
    $temp_path = file_directory_temp();
    if (!empty($temp_path)) {
      $ignore[] = realpath('./' . rtrim($temp_path, '/'));
    }

    // Add private files directory if it's set.
    $private_files = PrivateStream::basePath();
    if (!empty($private_files)) {
      // Remove leading slash if set.
      if (strrpos($private_files, '/') !== FALSE) {
        $private_files = substr($private_files, strrpos($private_files, '/') + 1);
      }
      $ignore[] = $private_files;
    }

    Drupal::moduleHandler()->alter('security_review_file_ignore', $ignore);
    return $ignore;
  }

}
