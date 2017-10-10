<?php

class BlindHash_SecurePassword_Model_Upgrade extends BlindHash_SecurePassword_Model_Encryption
{

    protected $resource;
    protected $read;
    protected $write;
    protected $table;

    public function __construct()
    {
        $this->resource = Mage::getSingleton('core/resource');
        $this->read = $this->resource->getConnection('core_read');
        $this->write = $this->resource->getConnection('core_write');
        $this->table = $this->resource->getTableName('customer_entity_text');
        parent::__construct();
    }

    /**
     * Upgrade all customers passwords from old hash to 
     * blind hash
     * 
     * @return int
     */
    public function UpgradeAllCustomerPasswords()
    {
        $attribute = Mage::getModel('eav/config')->getAttribute('customer', 'password_hash');
        $blindhashPrefix = self::PREFIX . self::DELIMITER;
        $query = "SELECT entity_id,value AS hash FROM {$this->table} WHERE attribute_id = {$attribute->getId()} AND value NOT like '$blindhashPrefix%' AND value <> '' ";
        $passwordList = $this->read->fetchAll($query);
        $count = 0;

        if (!$passwordList)
            return;

        foreach ($passwordList as $password) {
            $customerId = $password['entity_id'];
            $hash = $password['hash'];
            if ($this->_upgradeToBlindHash($hash, $customerId)) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Upgrade old md5 to blind hash
     * 
     * @param string $hash 
     * @param int $customerId
     * @return boolean
     */
    protected function _upgradeToBlindHash($hash, $customerId)
    {
        $hashUpdated = '';

        $hashArr = explode(BlindHash_SecurePassword_Model_Encryption::OLD_DELIMITER, $hash);

        switch (count($hashArr)) {
            case 1:
                $hashUpdated = $this->_blindhash($hash, $this->_getRandomString(self::DEFAULT_SALT_LENGTH), self::OLD_HASHING_WITHOUT_SALT_VERSION);
                break;
            case 2:
                $hashUpdated = $this->_blindhash($hashArr[0], $hashArr[1], self::OLD_HASHING_WITH_SALT_VERSION);
                break;
        }
        if (!empty($hashUpdated))
            return $this->write->update($this->table, array('value' => $hashUpdated), array('entity_id = ?' => $customerId));
    }
}
