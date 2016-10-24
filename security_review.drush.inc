<?php

/**
 * @file
 * Drush commands for Security Review module.
 */

/**
 * Implementation of hook_drush_command().
 */
function security_review_drush_command() {
  $items = array();
  
  $items['security-review'] = array(
    'callback' => 'security_review_drush',
    'aliases' => array('secrev'),
    'description' => "Run the Security Review checklist (hotototo)",
    'options' => array(
      'store' => 'Write results to the database',
      'log' => 'Log results of each check to watchdog, defaults to off',
      'lastrun' => 'Do not run the checklist, just print last results',
    ),
    'examples' => array(
      'secrev' => 'Run the checklist and output the results',
      'secrev --store' => 'Run the checklist, store, and output the results',
      'secrev --lastrun' => 'Output the stored results from the last run of the checklist'
    ),
    'outputformat' => array(
      'default' => 'table',
      'pipe-format' => 'csv',
      'fields-default' => array('message', 'status'),
      'field-labels' => array(
        'message' => 'Message',
        'status' => 'Status',
        'findings' => 'Findings',
      ),
      'output-data-type' => 'format-table',
    ),
  );
  $items['password-check-setup'] = array(
    'callback' => 'security_review_drush_hash_setup',
    'aliases' => array('passset'),
    'description' => "Create and load a rainbow table for password checking",
  );
  
  return $items;
}

/**
 * Implementation of hook_drush_help().
 */
function security_review_drush_help($section) {
  switch ($section) {
    case 'drush:security-review':
      return dt("Run configuration security checks on your Drupal site.");
    case 'drush:password-check-setup':
      return dt("Creates a table and fills it with dictionary words for rainbow testing.");
  }
}

/**
 * Run checklist and display results command.
 */
function security_review_drush() {
  module_load_include('inc', 'security_review');

  $store = drush_get_option('store');
  $log = drush_get_option('log');
  $lastrun = drush_get_option('lastrun');
  $checklist = module_invoke_all('security_checks');

  $output = array();
  if (!$lastrun) {
    // Unset file_perms of security_review because drush is running as a
    // different user.
    unset($checklist['security_review']['file_perms']);
    if ($store) {
      // Remove checks that are being skipped.
      $skipped = security_review_skipped_checks();
      if (!empty($skipped)) {
        foreach ($skipped as $module => $checks) {
          foreach ($checks as $check_name => $check) {
            unset($checklist[$module][$check_name]);
          }
          if (empty($checklist[$module])) {
            unset($checklist[$module]);
          }
        }
      }
    }
    // Run the checklist.
    $checklist_results = security_review_run($checklist, $log);
    if ($store) {
      security_review_store_results($checklist_results);
    }
    // Collect results.
    foreach ($checklist_results as $module => $checks) {
      foreach ($checks as $check_name => $check) {
        $check_name = $module . '-' . $check_name;
        if (!is_null($check['result'])) {
          $status = $check['result'] ? 'success' : 'error';
          if ($check_result = _security_review_drush_format_result($check, $status)) {
            $output[$check_name] = $check_result;
          }
        }
      }
    }
  }
  elseif ($lastrun) {
    // Retrieve results from last run of the checklist.
    $results = db_query("SELECT namespace, reviewcheck, result, lastrun, skip, skiptime, skipuid FROM {security_review}");
    while ($result = db_fetch_array($results)) {
      $checks[] = $result;
    }
    // Collect results.
    if (!empty($checks)) {
      foreach ($checks as $check) {
        $check_name = $check['namespace'] . '-' . $check['reviewcheck'];
        $check_data = array_merge($check, $checklist[$check['namespace']][$check['reviewcheck']]);
        $status = $check['result'] ? 'success' : 'error';
        if ($check_result = _security_review_drush_format_result($check_data, $status)) {
          $output[$check_name] = $check_result;
        }
      }
    }
  }

  return $output;
}

function _security_review_drush_format_result($check, $status) {
  if (is_null($check['result'])) {
    return;
  }

  return array(
    'message' => $check['title'],
    'status' => $status,
    'findings' => $check['value'],
  );
}

function security_review_drush_hash_setup() {
  $args = func_get_args();
  if (empty($args)) {
    drush_set_error('SECURITY_REVIEW_ERROR', dt('Dictionary filename required'));
    return FALSE;
  }
  if (file_exists($args[0])) {
    $ret = array();
    // Create the rainbow table.
    if (!db_table_exists('security_review_rainbow')) {
      $schema = array(
        'fields' => array(
          'hash_id' => array(
            'type' => 'serial',
          ),
          'hash_word' => array(
            'type' => 'varchar',
            'length' => 20,
          ),
          'hash_hash' => array(
            'type' => 'varchar',
            'length' => 32,
          ),
        ),
        'primary key' => array('hash_id'),
        'indexes' => array('hash_hash' => array('hash_hash')),
      );
      db_create_table($ret, 'security_review_rainbow', $schema);
    }
    // Put an index on users.pass.
    db_drop_index($ret, 'users', 'pass'); // Drop in case this has already run.
    db_add_index($ret, 'users', 'pass', array('pass'));
    
    $handle = fopen($args[0], 'r');
    if ($handle) {
      $count = 0;
      while (!feof($handle)) {
        $buffer = fgets($handle, 4096);
        $word = trim($buffer);
        $hash = md5($word);
        $sql = "INSERT INTO {security_review_rainbow} (hash_word, hash_hash) VALUES ('%s', '%s')";
        db_query($sql, $word, $hash);
        $count++;
      }
      fclose($handle);
      drush_log(dt('!count records inserted into rainbow table', array('!count' => $count)), 'success');
    }
  }
  else {
    drush_die('File not found');
  }
}
