<?php

class BlindHash_SecurePassword_Model_Observer
{

    /**
     * If the customer's password is not blind hashed then
     * replace it with new blind hash.
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

        $password = $observer->getPassword();
        $customer = $observer->getModel();

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

    /**
     * If the admin's password is not blind hashed then
     * replace it with new blind hash.
     *
     * @param Mage_Core_Model_Observer $observer observer with 
     * information about admin user
     *
     * @return void
     */
    public function adminUserAuthenticateAfter($observer)
    {
        if (!(boolean) Mage::getStoreConfig(
                'blindhash/securepassword/enabled'
            )) {
            return;
        }

        $helper = Mage::helper('core');
        $encrypter = $helper->getEncryptor();

        $user = $observer->getUser();
        $password = $observer->getPassword();

        if (!$encrypter->IsBlindHashed($user->getPassword())) {
            $user->setPassword($observer->getPassword());
            $user->save();
        }
    }

    /**
     * If the api password is hashed the old way, we replace it
     *
     * @param Mage_Core_Model_Observer $observer Observer with API
     * user informations
     *
     * @return void
     */
    public function apiUserAuthenticated($observer)
    {
        if (!(boolean) Mage::getStoreConfig(
                'blindhash/securepassword/enabled'
            )) {
            return;
        }

        $helper = Mage::helper('core');
        $encrypter = $helper->getEncryptor();

        $user = $observer->getModel();
        $password = $observer->getApiKey();

        if (!$encrypter->IsBlindHashed($user->getApiKey())) {
            $user->setApiKey($observer->getApiKey());
            $user->save();
        }
    }

    /**
     * Verify Tap Link App Id if it is not valid then show error message 
     * and dont allow to enable blindhash
     * 
     * @param Mage_Core_Model_Observer $observer Observer with system config
     * @return void
     */
    public function verifyTapLinkApi($observer)
    {
        if (!(boolean) Mage::getStoreConfig(
                'blindhash/securepassword/enabled'
            )) {
            return;
        }
        $apiKey = Mage::getStoreConfig('blindhash/securepassword/api_key');

        $ch = curl_init();
        $url = 'https://api.taplink.co/' . $apiKey;

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $output = curl_exec($ch);
        curl_close($ch);
        if (empty(json_decode($output, true))) {
            Mage::getModel('core/config')->saveConfig('blindhash/securepassword/enabled', 0);
            Mage::getSingleton('adminhtml/session')->addError(Mage::helper('blindhash_securepassword')->__('Api key is not valid.'), true);
        }
    }
}
