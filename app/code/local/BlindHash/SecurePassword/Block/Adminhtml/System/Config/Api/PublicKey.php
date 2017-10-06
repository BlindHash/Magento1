<?php

class BlindHash_SecurePassword_Block_Adminhtml_System_Config_Api_PublicKey extends Mage_Adminhtml_Block_System_Config_Form_Field
{

    protected function _getElementHtml(Varien_Data_Form_Element_Abstract $element)
    {
        $element->setDisabled('disabled');
        return $element->getElementHtml();
    }
}
