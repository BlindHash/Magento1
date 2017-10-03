<?php

class BlindHash_SecurePassword_Model_Observer
{

    /**
     * If the customer's password is an old MD5 hash, and the shop-owner
     * wants them to replaced, DO IT.
     *
     * @param Mage_Core_Model_Observer $observer Observer with
     * customer informations
     *
     * @return void
     */
    public function customerCustomerAuthenticated($observer)
    {
        if (!(boolean) Mage::getStoreConfig(
                'blindhash/securepassword/enabled'
            )) {
            return;
        }

        // check wether the password is an old one
        $password = $observer->getPassword();
        /* @var $customer Mage_Customer_Model_Customer */
        $customer = $observer->getModel();

        /* @var $helper Mage_Core_Helper_Data */
        $helper = Mage::helper('core');
        $encrypter = $helper->getEncryptor();

        // if the hash validates against the old hashing method,
        // replace with new hash
        if (!$encrypter->IsBlindHashed($customer->getPasswordHash())
        ) {
            $customer->setPassword($password);
            $customer->save();
        }
    }
}
