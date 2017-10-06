<?php

class BlindHash_SecurePassword_Block_Adminhtml_System_Config_Total_Blindhashes extends Mage_Adminhtml_Block_System_Config_Form_Field
{

    protected function _getElementHtml()
    {
        return Mage::getModel('blindhash_securepassword/hashes')->getTotalBlindHashes();
    }
}
