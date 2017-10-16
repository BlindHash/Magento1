<?php

class BlindHash_SecurePassword_Block_Adminhtml_System_Config_Downgrade_Button extends Mage_Adminhtml_Block_System_Config_Form_Field
{

    protected function _getElementHtml(Varien_Data_Form_Element_Abstract $element)
    {
        $this->setElement($element);
        $url = Mage::helper("adminhtml")->getUrl('adminhtml/downgrade/hashes');

        $downgradeHashesJs = " <script type='text/javascript'>
            function downgradeHashes(){
            
                var privateKey = document.getElementById('blindhash_securepassword_api_private_key'); 
                if(privateKey.style.display == 'none'){
                    privateKey.style.display = 'block';
                }  
                
                if(privateKey.value)
                    setLocation('{$url}?private_key='+privateKey.value);
                else
                    alert('Please provide private key in below input to downgrade hashes');
                }</script>";


        $html = $this->getLayout()->createBlock('adminhtml/widget_button')
            ->setType('button')
            ->setClass('scalable')
            ->setLabel('Downgrade Hashes!')
            ->setOnClick("downgradeHashes()")
            ->toHtml();

        return $html.$downgradeHashesJs;
    }
}
