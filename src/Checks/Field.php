<?php

namespace Drupal\security_review\Checks;

use Drupal\field\Entity\FieldStorageConfig;
use Drupal\security_review\Check;
use Drupal\security_review\CheckResult;

/**
 * Checks for Javascript and PHP in submitted content.
 */
class Field extends Check {

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
    return 'Content';
  }

  /**
   * {@inheritdoc}
   */
  public function getMachineTitle() {
    return 'field';
  }

  /**
   * {@inheritdoc}
   */
  public function run() {
    $result = CheckResult::SUCCESS;
    $findings = [];

    $field_types = [
      'text_with_summary',
      'text_long',
    ];
    $tags = [
      'Javascript' => 'script',
      'PHP' => '?php',
    ];

    /** @var \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager */
    $entity_type_manager = \Drupal::service('entity_type.manager');
    /** @var \Drupal\Core\Entity\EntityFieldManagerInterface $field_manager */
    $field_manager = \Drupal::service('entity_field.manager');
    foreach ($field_manager->getFieldMap() as $entity_type_id => $fields) {
      $field_storage_definitions = $field_manager->getFieldStorageDefinitions($entity_type_id);
      foreach ($fields as $field_name => $field) {
        if (!isset($field_storage_definitions[$field_name])) {
          continue;
        }
        $field_storage_definition = $field_storage_definitions[$field_name];
        if (in_array($field_storage_definition->getType(), $field_types)) {
          if ($field_storage_definition instanceof FieldStorageConfig) {
            $table = $entity_type_id . '__' . $field_name;
            $separator = '_';
            $id = 'entity_id';
          }
          else {
            $table = $entity_type_id . '_field_data';
            $separator = '__';
            $id = $entity_type_manager->getDefinition($entity_type_id)->getKey('id');
          }
          $rows = \Drupal::database()->select($table, 't')
            ->fields('t')
            ->execute()
            ->fetchAll();
          foreach ($rows as $row) {
            foreach (array_keys($field_storage_definition->getSchema()['columns']) as $column) {
              $column_name = $field_name . $separator . $column;
              foreach ($tags as $vulnerability => $tag) {
                if (strpos($row->{$column_name}, '<' . $tag) !== FALSE) {
                  // Vulnerability found.
                  $findings[$entity_type_id][$row->{$id}][$field_name][] = $vulnerability;
                }
              }
            }
          }
        }
      }
    }

    if (!empty($findings)) {
      $result = CheckResult::FAIL;
    }

    return $this->createResult($result, $findings);
  }

  /**
   * {@inheritdoc}
   */
  public function help() {
    $paragraphs = [];
    $paragraphs[] = $this->t('Script and PHP code in content does not align with Drupal best practices and may be a vulnerability if an untrusted user is allowed to edit such content. It is recommended you remove such contents.');

    return [
      '#theme' => 'check_help',
      '#title' => $this->t('Dangerous tags in content'),
      '#paragraphs' => $paragraphs,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function evaluate(CheckResult $result) {
    $findings = $result->findings();
    if (empty($findings)) {
      return [];
    }

    $paragraphs = [];
    $paragraphs[] = $this->t('The following items potentially have dangerous tags.');

    $items = [];
    foreach ($findings as $entity_type_id => $entities) {
      foreach ($entities as $entity_id => $fields) {
        $entity = $this->entityManager()
          ->getStorage($entity_type_id)
          ->load($entity_id);

        foreach ($fields as $field => $finding) {
          $url = $entity->toUrl('edit-form');
          if ($url === NULL) {
            $url = $entity->toUrl();
          }
          $items[] = $this->t(
            '@vulnerabilities found in <em>@field</em> field of <a href=":url">@label</a>',
            [
              '@vulnerabilities' => implode(' and ', $finding),
              '@field' => $field,
              '@label' => $entity->label(),
              ':url' => $url->toString(),
            ]
          );
        }
      }
    }

    return [
      '#theme' => 'check_evaluation',
      '#paragraphs' => $paragraphs,
      '#items' => $items,
    ];
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
    foreach ($findings as $entity_type_id => $entities) {
      foreach ($entities as $entity_id => $fields) {
        $entity = $this->entityManager()
          ->getStorage($entity_type_id)
          ->load($entity_id);

        foreach ($fields as $field => $finding) {
          $url = $entity->toUrl('edit-form');
          if ($url === NULL) {
            $url = $entity->toUrl();
          }
          $output .= "\t" . $this->t(
              '@vulnerabilities in @field of :link',
              [
                '@vulnerabilities' => implode(' and ', $finding),
                '@field' => $field,
                ':link' => $url->toString(),
              ]
            ) . "\n";
        }
      }
    }

    return $output;
  }

  /**
   * {@inheritdoc}
   */
  public function getMessage($result_const) {
    switch ($result_const) {
      case CheckResult::SUCCESS:
        return $this->t('Dangerous tags were not found in any submitted content (fields).');

      case CheckResult::FAIL:
        return $this->t('Dangerous tags were found in submitted content (fields).');

      default:
        return $this->t('Unexpected result.');
    }
  }

}
