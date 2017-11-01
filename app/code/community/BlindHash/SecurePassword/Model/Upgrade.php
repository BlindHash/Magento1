<?php

class BlindHash_SecurePassword_Model_Upgrade extends BlindHash_SecurePassword_Model_Encryption
{

    protected $resource;
    protected $read;
    protected $write;
    protected $customerPasswordTable;
    protected $adminPasswordTable;
    protected $apiPasswordTable;
    protected $prefix;
    protected $count = 0;

    const LIMIT = 100;

    public function __construct()
    {
        $this->prefix = self::PREFIX . self::DELIMITER;
        $this->resource = Mage::getSingleton('core/resource');
        $this->read = $this->resource->getConnection('core_read');
        $this->write = $this->resource->getConnection('core_write');
        $this->customerPasswordTable = $this->resource->getTableName('customer_entity_text');
        $this->adminPasswordTable = $this->resource->getTableName('admin_user');
        $this->apiPasswordTable = $this->resource->getTableName('api_user');
        parent::__construct();
    }

    /**
     * Upgrade all simple hashes to blind hashes
     * @return int
     */
    public function upgradeAllPasswords()
    {
        $startTime = microtime(true);
        $this->upgradeAllAdminPasswords();
        $this->upgradeAllApiPasswords();
        $this->upgradeAllCustomerPasswords();
        $timeTaken = round(microtime(true) - $startTime, 4);
        Mage::log("BlindHash upgrade completed in {$timeTaken}", null, 'blindHash.log');
        return $this->count;
    }

    /**
     * Upgrade all simple hashes to blind hashes of admin users
     * @return int
     */
    protected function upgradeAllAdminPasswords()
    {
        $query = "SELECT user_id,password AS hash FROM {$this->adminPasswordTable} WHERE password NOT like '$this->prefix%' AND password <> ''";
        $passwordList = $this->read->fetchAll($query);

        if (!$passwordList)
            return;

        foreach ($passwordList as $password)
            $this->_convertToBlindHash($password['hash'], $password['user_id'], $this->adminPasswordTable, 'password', 'user_id');
    }

    /**
     * Upgrade all simple hashes to blind hashes of api users
     * @return int
     */
    protected function upgradeAllApiPasswords()
    {
        $query = "SELECT user_id,api_key AS hash FROM {$this->apiPasswordTable} WHERE api_key NOT like '$this->prefix%' AND api_key <> ''";
        $passwordList = $this->read->fetchAll($query);

        if (!$passwordList)
            return;

        foreach ($passwordList as $password)
            $this->_convertToBlindHash($password['hash'], $password['user_id'], $this->apiPasswordTable, 'api_key', 'user_id');
    }

    /**
     * Upgrade all simple hashes to blind hashes of customers
     * @return int
     */
    protected function upgradeAllCustomerPasswords()
    {
        $attribute = Mage::getModel('eav/config')->getAttribute('customer', 'password_hash');
        $limit = self::LIMIT;
        while (true) {

            $query = "SELECT entity_id,value AS hash FROM {$this->customerPasswordTable} WHERE attribute_id = {$attribute->getId()} AND value NOT like '$this->prefix%' AND value <> '' limit {$limit}";
            $passwordList = $this->read->fetchAll($query);

            if (!$passwordList)
                break;

            foreach ($passwordList as $password)
                $this->_convertToBlindHash($password['hash'], $password['entity_id'], $this->customerPasswordTable, 'value', 'entity_id');
        }
    }

    /**
     * Convert old hash to blind hash and save to DB
     * 
     * @param string $hash
     * @param int $id
     * @param string $table
     * @param string $field1
     * @param string $field2
     * @return void
     */
    protected function _convertToBlindHash($hash, $id, $table, $field1, $field2)
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

        if (empty($hashUpdated))
            return;

        if ($this->write->update($table, array($field1 => $hashUpdated), array($field2 . ' = ?' => $id)))
            $this->count++;
    }
}
