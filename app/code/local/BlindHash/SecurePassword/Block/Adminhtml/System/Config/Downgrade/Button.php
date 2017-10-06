<?php

class BlindHash_SecurePassword_Block_Adminhtml_System_Config_Downgrade_Button extends Mage_Adminhtml_Block_System_Config_Form_Field
{

    protected function _getElementHtml(Varien_Data_Form_Element_Abstract $element)
    {
        $this->setElement($element);
        $url = Mage::helper("adminhtml")->getUrl('adminhtml/downgrade/hashes');

        $html = $this->getLayout()->createBlock('adminhtml/widget_button')
            ->setType('button')
            ->setClass('scalable')
            ->setLabel('Downgrade Hashes!')
            ->setOnClick("setLocation('$url')")
            ->toHtml();

        return $html;
    }
}
