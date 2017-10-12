<?php

class BlindHash_SecurePassword_Adminhtml_DowngradeController extends Mage_Adminhtml_Controller_Action
{

    public function hashesAction()
    {
        $count = Mage::getModel('blindhash_securepassword/downgrade')->downgradeAllPasswords();
        if ($count) {
            Mage::getSingleton('adminhtml/session')->addSuccess(Mage::helper('blindhash_securepassword')->__('%s password(s) has been downgraded to old hash.', $count));
        } else {
            Mage::getSingleton('adminhtml/session')->addNotice(Mage::helper('blindhash_securepassword')->__('There are no blindhash passwords.'));
        }
        $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
    }
}
