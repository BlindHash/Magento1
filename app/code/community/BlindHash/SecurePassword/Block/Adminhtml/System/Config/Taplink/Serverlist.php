<?php

class BlindHash_SecurePassword_Block_Adminhtml_System_Config_Taplink_Serverlist extends Mage_Adminhtml_Block_System_Config_Form_Field
{

    protected function _getElementHtml(Varien_Data_Form_Element_Abstract $element)
    {
        $element->setDisabled('disabled');
        return parent::_getElementHtml($element);
    }
}
