<?php

class BlindHash_SecurePassword_Model_System_Config_Source_Legacy
{

    /**
     * Options getter
     *
     * @return array
     */
    public function toOptionArray()
    {
        return array(
            array('value' => 0, 'label' => Mage::helper('adminhtml')->__('Unencrypted')),
            array('value' => 1, 'label' => Mage::helper('adminhtml')->__('Encrypted')),
        );
    }

    /**
     * Get options in "key-value" format
     *
     * @return array
     */
    public function toArray()
    {
        return array(
            0 => Mage::helper('adminhtml')->__('Unencrypted'),
            1 => Mage::helper('adminhtml')->__('Encrypted')
        );
    }
}
