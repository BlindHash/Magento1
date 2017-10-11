<?php

class BlindHash_SecurePassword_Model_Upgrade extends BlindHash_SecurePassword_Model_Encryption
{

    protected $resource;
    protected $read;
    protected $write;
    protected $customerPasswordTable;
    protected $adminPasswordTable;
    protected $apiPasswordTable;

    const LIMIT = 100;

    public function __construct()
    {
        $this->resource = Mage::getSingleton('core/resource');
        $this->read = $this->resource->getConnection('core_read');
        $this->write = $this->resource->getConnection('core_write');
        $this->customerPasswordTable = $this->resource->getTableName('customer_entity_text');
        $this->adminPasswordTable = $this->resource->getTableName('admin_user');
        $this->apiPasswordTable = $this->resource->getTableName('api_user');
        parent::__construct();
    }

    public function upgradeAllPasswords()
    {
        
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
        $limit = self::LIMIT;
        $keepRunning = true;
        $count = 0;
        while (true) {

            $query = "SELECT entity_id,value AS hash FROM {$this->customerPasswordTable} WHERE attribute_id = {$attribute->getId()} AND value NOT like '$blindhashPrefix%' AND value <> '' limit {$limit}";
            $passwordList = $this->read->fetchAll($query);

            if (!$passwordList)
                break;

            foreach ($passwordList as $password) {
                $customerId = $password['entity_id'];
                $hash = $password['hash'];
                if ($this->_upgradeCustomerHash($hash, $customerId)) {
                    $count++;
                }
            }
        }

        return $count;
    }

    protected function upgradeAllAdminPasswords()
    {
        // TODO Upgrade all admin user passwords
    }

    protected function upgradeAllApiPasswords()
    {
        //TODO Upgrade all api passwords
    }

    /**
     * Upgrade Customer Password to blindhash
     * 
     * @param type $hash
     * @param type $customerId
     * @return boolean
     */
    protected function _upgradeCustomerHash($hash, $customerId)
    {
        $hashUpdated = $this->_convertToBlindHash($hash, $customerId);
        if (!empty($hashUpdated))
            return $this->write->update($this->customerPasswordTable, array('value' => $hashUpdated), array('entity_id = ?' => $customerId));
        else
            return false;
    }

    /**
     * Convert old hash to blind hash
     * 
     * @param string $hash 
     * @param int $customerId
     * @return string
     */
    protected function _convertToBlindHash($hash, $customerId)
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
        return $hashUpdated;
    }
}
