<?php

class BlindHash_SecurePassword_Model_Downgrade extends BlindHash_SecurePassword_Model_Encryption
{

    protected $resource;
    protected $read;
    protected $write;
    protected $customerPasswordTable;
    protected $adminPasswordTable;
    protected $apiPasswordTable;
    protected $prefix;
    protected $count = 0;
    protected $privateKey;

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
     * Downgrade all blind hashes to simple magento hashes
     * @return int
     */
    public function downgradeAllPasswords($privateKey)
    {
        $startTime = microtime(true);
        $this->privateKey = $privateKey;
        $this->downgradeAllAdminPasswords();
        $this->downgradeAllApiPasswords();
        $this->downgradeAllCustomerPasswords();
        $timeTaken = round(microtime(true) - $startTime, 4);
        Mage::log("BlindHash downgrade completed in {$timeTaken}", null, 'blindHash.log');
        return $this->count;
    }

    /**
     * Downgrade all blina hashes of admin users
     * @return int
     */
    protected function downgradeAllAdminPasswords()
    {
        $query = "SELECT user_id,password AS hash FROM {$this->adminPasswordTable} WHERE password like '$this->prefix%' ";
        $passwordList = $this->read->fetchAll($query);

        if (!$passwordList)
            return;

        $count = 0;
        foreach ($passwordList as $password)
            $this->_convertToOldHash($password['hash'], $password['user_id'], $this->adminPasswordTable, 'password', 'user_id');
    }

    /**
     * Downgrade all blina hashes of api users
     * @return int
     */
    protected function downgradeAllApiPasswords()
    {
        $query = "SELECT user_id,api_key AS hash FROM {$this->apiPasswordTable} WHERE api_key like '$this->prefix%' ";
        $passwordList = $this->read->fetchAll($query);

        if (!$passwordList)
            return;

        foreach ($passwordList as $password)
            $this->_convertToOldHash($password['hash'], $password['user_id'], $this->apiPasswordTable, 'api_key', 'user_id');
    }

    /**
     * Downgrade all blina hashes of customers
     * @return int
     */
    public function downgradeAllCustomerPasswords()
    {
        $attribute = Mage::getModel('eav/config')->getAttribute('customer', 'password_hash');
        $limit = self::LIMIT;
        while (true) {

            $query = "SELECT entity_id,value AS hash FROM {$this->customerPasswordTable} WHERE attribute_id = {$attribute->getId()} AND value like '$this->prefix%' limit {$limit}";
            $passwordList = $this->read->fetchAll($query);

            if (!$passwordList)
                break;

            foreach ($passwordList as $password)
                $this->_convertToOldHash($password['hash'], $password['entity_id'], $this->customerPasswordTable, 'value', 'entity_id');
        }
    }

    /**
     * Downgrade password from blindhash to old md5 and update to DB
     * 
     * @param string $hash
     * @param int $id
     * @param string $table
     * @param string $field1
     * @param string $field2
     * @return void
     */
    protected function _convertToOldHash($hash, $id, $table, $field1, $field2)
    {
        $hashArr = explode(self::DELIMITER, $hash);
        if ((count($hashArr) < 5)) {
            return;
        }

        list($T, $expectedHash2Hex, $salt, $version, $hash1Encrypted) = $hashArr;

        $hash1 = $this->taplink->decrypt($this->publicKeyHex, $this->privateKey, $hash1Encrypted);

        // If decryption fails then get back to admin with error
        if ($hash1Encrypted && empty($hash1)) {
            Mage::getSingleton('adminhtml/session')->addError(Mage::helper('blindhash_securepassword')->__('Not able to decrypt password.'));
            $url = Mage::helper("adminhtml")->getUrl('adminhtml/system_config/edit', array('section' => 'blindhash'));
            $response = Mage::app()->getFrontController()->getResponse();
            $response->setRedirect($url);
            $response->sendResponse();
            exit;
        }

        if ($version != self::OLD_HASHING_WITHOUT_SALT_VERSION) {
            $hash1 .= ':' . $salt;
        }

        if ($this->write->update($table, array($field1 => $hash1), array($field2 . ' = ?' => $id)))
            $this->count++;
    }
}
