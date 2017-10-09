<?php

class BlindHash_SecurePassword_Adminhtml_UpgradeController extends Mage_Adminhtml_Controller_Action
{

    public function hashesAction()
    {
        $upgradeModel = Mage::getModel('blindhash_securepassword/upgrade');
        $count = $upgradeModel->UpgradeAllCustomerPasswords();
        if ($count) {
            Mage::getSingleton('adminhtml/session')->addSuccess(Mage::helper('blindhash_securepassword')->__('%s password(s) has been upgraded to blind hash.', $count));
        } else {
            Mage::getSingleton('adminhtml/session')->addNotice(Mage::helper('blindhash_securepassword')->__('There are no old hash passwords left.'));
        }
        $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
    }
}
