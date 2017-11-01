<?php

class BlindHash_SecurePassword_Adminhtml_UpgradeController extends Mage_Adminhtml_Controller_Action
{

    public function hashesAction()
    {
        if (!(boolean) Mage::getStoreConfig('blindhash/securepassword/enabled')) {
            Mage::getSingleton('adminhtml/session')->addNotice(Mage::helper('blindhash_securepassword')->__('Please enable Blind hash Hashing before upgrade.'));
            $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
            return;
        }

        $count = Mage::getModel('blindhash_securepassword/upgrade')->upgradeAllPasswords();
        if ($count) {
            Mage::getSingleton('adminhtml/session')->addSuccess(Mage::helper('blindhash_securepassword')->__('%s password(s) has been upgraded to blind hash.', $count));
        } else {
            Mage::getSingleton('adminhtml/session')->addNotice(Mage::helper('blindhash_securepassword')->__('There are no old hash passwords left.'));
        }
        $this->_redirect('adminhtml/system_config/edit', array('section' => 'blindhash'));
    }
}
