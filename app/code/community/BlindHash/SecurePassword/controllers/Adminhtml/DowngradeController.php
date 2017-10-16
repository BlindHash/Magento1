<?php

class BlindHash_SecurePassword_Adminhtml_DowngradeController extends Mage_Adminhtml_Controller_Action
{

    public function hashesAction()
    {
        if ($privateKey = $this->getRequest()->getParam('private_key'))
            $count = Mage::getModel('blindhash_securepassword/downgrade')->downgradeAllPasswords($privateKey);
        else
            Mage::getSingleton('adminhtml/session')->addError(Mage::helper('blindhash_securepassword')->__('Please provide private key to downgrade blindhashes.'));

        if ($count) {
            Mage::getSingleton('adminhtml/session')->addSuccess(Mage::helper('blindhash_securepassword')->__('%s password(s) has been downgraded to old hash.', $count));
        } else {
            Mage::getSingleton('adminhtml/session')->addNotice(Mage::helper('blindhash_securepassword')->__('There are no blindhash passwords.'));
        }
        $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
    }
}
