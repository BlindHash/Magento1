<?php

class BlindHash_SecurePassword_Helper_Data extends Mage_Core_Helper_Abstract
{

    /**
     * Update Request Counters
     * @param array $counterArray
     */
    public function updatedBlindHashRequestCounters($counterArray)
    {
        if (!(boolean) Mage::getStoreConfig(
                'blindhash/request/request_statistics'
            )) {
            return;
        }
        Mage::getModel('core/config')->saveConfig('blindhash/request/total_error_count', $counterArray->total_error_count + (int) Mage::getStoreConfig('blindhash/request/total_error_count'))->cleanCache();
        Mage::getModel('core/config')->saveConfig('blindhash/request/total_request_count', $counterArray->total_request_count + (int) Mage::getStoreConfig('blindhash/request/total_request_count'))->cleanCache();
        Mage::getModel('core/config')->saveConfig('blindhash/request/total_retry_count', $counterArray->total_retry_count + (int) Mage::getStoreConfig('blindhash/request/total_retry_count'))->cleanCache();
    }
}
