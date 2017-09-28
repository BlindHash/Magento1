<?php
$installer = $this;

$installer->startSetup();

$installer->getConnection()->modifyColumn(
    $installer->getTable('api/user'), 'api_key', 'TEXT default NULL'
);

$installer->endSetup();