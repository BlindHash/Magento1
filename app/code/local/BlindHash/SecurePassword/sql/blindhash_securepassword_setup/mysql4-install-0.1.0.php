<?php
$installer = $this;

$installer->startSetup();

$installer->getConnection()->modifyColumn(
    $installer->getTable('admin/user'), 'password', 'TEXT default NULL'
);

$installer->getConnection()->modifyColumn(
    $installer->getTable('api/user'), 'api_key', 'TEXT default NULL'
);

$newAttribute = Mage::getSingleton('eav/config')
    ->getAttribute('customer', 'password_hash');
$currentAttribute = clone $newAttribute;
if ('text' !== $currentAttribute->getBackendType()) {

    $installer->getConnection()->beginTransaction();
    try {
        $newAttribute = clone $currentAttribute;
        // Change Backend Type to Text
        $newAttribute->setBackendType('text');

        $currentTable = $currentAttribute->getBackend()->getTable();
        $newTable = $newAttribute->getBackend()->getTable();

        // Copy password hashes over to the text attribute value table
        $cols = array('entity_type_id', 'attribute_id', 'entity_id', 'value');
        $sql = $installer->getConnection()->select()
            ->from($currentTable, $cols)
            ->where('attribute_id=?', $currentAttribute->getId())
            ->insertFromSelect($newTable, $cols);
        $installer->getConnection()->query($sql);

        $installer->updateAttribute(
            'customer', 'password_hash', 'backend_type', 'text'
        );

        // Delete values from old value table
        $installer->getConnection()->delete(
            $currentTable, array('attribute_id=?' => $currentAttribute->getId())
        );
        $installer->getConnection()->commit();
    } catch (Exception $e) {
        $installer->getConnection()->rollBack();
        throw $e;
    }
}

$installer->endSetup();
