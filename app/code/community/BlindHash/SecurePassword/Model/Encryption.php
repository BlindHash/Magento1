<?php
$ExternalLibPath = Mage::getModuleDir('', 'BlindHash_SecurePassword') . DS . 'lib' . DS;

require_once $ExternalLibPath . 'Client.php';
require_once $ExternalLibPath . 'Response.php';

class BlindHash_SecurePassword_Model_Encryption extends Mage_Core_Model_Encryption implements BlindHash_SecurePassword_Model_Encryption_Interface
{

    const DEFAULT_SALT_LENGTH = 64;
    const HASH_ALGORITHM = 'sha512';
    const DELIMITER = '$';
    const OLD_DELIMITER = ':';
    const PREFIX = 'T';
    const OLD_HASHING_WITHOUT_SALT_VERSION = 1; // Hashing magento way without salt
    const OLD_HASHING_WITH_SALT_VERSION = 2; // Hashing magento way with salt
    const NEW_HASHING_VERSION = 3; // Hashing using blindhash

    //Instance of BlindHash API

    protected $taplink;

    public function __construct()
    {
        //Get Api key from System Config
        $appId = Mage::getStoreConfig('blindhash/securepassword/api_key');
        $this->taplink = new Client($appId);
    }

    /**
     * Generate a [salted] hash.
     *
     * $salt can be:
     * false - old Mage_Core_Model_Encryption::hash() function will be used
     * integer - a random with specified length will be generated
     * string - use the given salt for _blindhash
     *
     * @param string $plainText
     * @param mixed  $salt
     *
     * @return string
     */
    public function getHash($plainText, $salt = false)
    {
        if (!(boolean) Mage::getStoreConfig(
                'blindhash/securepassword/enabled'
            )) {
            return parent::getHash($plainText, $salt);
        }

        if ($salt === true) {
            $salt = self::DEFAULT_SALT_LENGTH;
        }

        if (is_integer($salt)) {
            $salt = $this->_getRandomString($salt);
        }

        // The hash to send to TapLink is the SHA512-HMAC(salt, password)
        $res = $this->taplink->newPassword(hash_hmac(self::HASH_ALGORITHM, $plainText, $salt));
        if ($res->error) {
            Mage::logException($res->error);
        }

        // Adding magento hash as last parameter
        $hash1 = parent::getHash($plainText, $salt);

        return @implode(self::DELIMITER, [self::PREFIX, $res->hash2Hex, $salt, $version, $hash1]);
    }

    protected function _blindhash($hash, $salt, $version = self::NEW_HASHING_VERSION)
    {
        // The hash to send to TapLink is the SHA512-HMAC(salt, password)
        $res = $this->taplink->newPassword(hash_hmac(self::HASH_ALGORITHM, $hash, $salt));

        if ($res->error) {
            Mage::logException($res->error);
        }

        return @implode(self::DELIMITER, [self::PREFIX, $res->hash2Hex, $salt, $version, $hash]);
    }

    /**
     * Check if string is blind hashed
     * 
     * @param string $hash
     * @return bool 
     */
    public function IsBlindHashed($hash)
    {
        $hashArr = explode(self::DELIMITER, $hash);
        return (count($hashArr) >= 4) ? true : false;
    }

    /**
     * Validate hash against hashing method (with or without salt)
     *
     * @param string $password
     * @param string $hash
     * @return bool
     * @throws \Exception
     */
    public function validateHash($password, $hash)
    {
        if (!$this->IsBlindHashed($hash)) {
            return parent::validateHash($password, $hash);
        }

        // Get the pieces of the puzzle.
        $hashArr = explode(self::DELIMITER, $hash);
        list($T, $expectedHash2Hex, $salt, $version) = $hashArr;

        if ($version == self::OLD_HASHING_WITHOUT_SALT_VERSION) {
            $password = parent::getHash($password);
        }

        if ($version == self::OLD_HASHING_WITH_SALT_VERSION) {
            $password = @explode(BlindHash_SecurePassword_Model_Encryption::OLD_DELIMITER, parent::getHash($password, $salt))[0];
        }

        $res = $this->taplink->verifyPassword(hash_hmac(self::HASH_ALGORITHM, $password, $salt), $expectedHash2Hex);
        if ($res->error) {
            Mage::logException($res->error);
        }
        return $res->matched;
    }

    /**
     * Get hexadecimal random string
     *
     * @param int         $length
     * @param null|string $chars
     * @return string
     */
    protected function _getRandomString($length)
    {
        $str = '';

        if (function_exists('random_bytes')) {
            $str = bin2hex(random_bytes($length));
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            // use openssl lib if it is installed
            $str = bin2hex(openssl_random_pseudo_bytes($length));
        } elseif ($fp = @fopen('/dev/urandom', 'rb')) {
            // attempt to use /dev/urandom if it exists but openssl isn't available
            $str = bin2hex(@fread($fp, $length));
            fclose($fp);
        } else {
            Mage::logException("Can't generate cryptographic radom string for hashing.");
        }
        return $str;
    }

    public function getPublicKey()
    {
        return $this->taplink->getPublicKey();
    }
}
