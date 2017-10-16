<?php

class BlindHash_SecurePassword_Block_Adminhtml_System_Config_Encryption_Available extends Mage_Adminhtml_Block_System_Config_Form_Field
{

    protected function _getElementHtml(Varien_Data_Form_Element_Abstract $element)
    {
        return (Mage::getStoreConfig('blindhash/securepassword/encryption_available')) ? 'Yes' : 'No';
    }
}
