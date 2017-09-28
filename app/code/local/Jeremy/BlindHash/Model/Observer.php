<?php

class Jeremy_BlindHash_Model_Observer
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
                'jeremy/blindhash/enabled'
            )) {
            return;
        }

        // TODO blindhash customer password
    }

    /**
     * If the admin's password is an old MD5 hash, and the shop-owner wants
     * them to replaced, DO IT.
     *
     * @param Mage_Core_Model_Observer $observer observer with information about
     * admin user
     *
     * @return void
     */
    public function adminUserAuthenticateAfter($observer)
    {
        if (!(boolean) Mage::getStoreConfig(
                'jeremy/blindhash/enabled'
            )) {
            return;
        }

        // TODO blindhash admin password
    }
}
