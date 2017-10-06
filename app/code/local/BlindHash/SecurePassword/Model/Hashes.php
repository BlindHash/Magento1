<?php

class BlindHash_SecurePassword_Model_Hashes extends Mage_Core_Model_Abstract
{

    protected $resource;
    protected $read;
    protected $write;
    protected $table;
    protected $attributeId;

    public function _construct()
    {
        $this->resource = Mage::getSingleton('core/resource');
        $this->read = $this->resource->getConnection('core_read');
        $this->write = $this->resource->getConnection('core_write');
        $this->table = $this->resource->getTableName('customer_entity_text');
        $attribute = Mage::getModel('eav/config')->getAttribute('customer', 'password_hash');
        $this->attributeId = $attribute->getId();
    }

    /**
     * Get Total Customer Password Hashes Count
     * 
     * @return int
     */
    public function getTotalHashes()
    {
        $query = "SELECT count(*) FROM {$this->table} WHERE attribute_id = {$this->attributeId}";
        return $this->read->fetchOne($query);
    }

    /**
     * Get Total Customer Blind Hash Protected Password Hashes Count
     * 
     * @return int
     */
    public function getTotalBlindHashes()
    {
        $blindhashPrefix = BlindHash_SecurePassword_Model_Encryption::PREFIX . BlindHash_SecurePassword_Model_Encryption::DELIMITER;
        $query = "SELECT count(*) FROM {$this->table} WHERE attribute_id = {$this->attributeId} AND value like '$blindhashPrefix%'";
        return $this->read->fetchOne($query);
    }
}
