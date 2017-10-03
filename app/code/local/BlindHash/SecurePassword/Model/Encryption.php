<?php
$ExternalLibPath = Mage::getModuleDir('', 'BlindHash_SecurePassword') . DS . 'lib' . DS;

require_once $ExternalLibPath . 'Client.php';
require_once $ExternalLibPath . 'Response.php';

class BlindHash_SecurePassword_Model_Encryption extends Mage_Core_Model_Encryption implements BlindHash_SecurePassword_Model_Encryption_Interface
{

    const DEFAULT_SALT_LENGTH = 64;
    const HASH_ALGORITHM = 'sha512';
    const DELIMITER = '$';
    const PREFIX = 'T';

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
     * @param string $plaintext
     * @param mixed  $salt
     *
     * @return string
     */
    public function getHash($plaintext, $salt = false)
    {
        if ($salt === false) {
            return $this->hash($plaintext);
        }

        if ($salt === true) {
            $salt = self::DEFAULT_SALT_LENGTH;
        }

        if (is_integer($salt)) {
            $salt = $this->_getRandomString($salt);
        }

        // The hash to send to TapLink is the SHA512-HMAC(salt, password)
        $res = $this->taplink->newPassword(hash_hmac(self::HASH_ALGORITHM, $plaintext, $salt));
        if ($res->error) {
            Mage::throwException($res->error);
        }

        // The format is <T>:<hash2hex>:<salt>:<taplink.version>
        return @implode(self::DELIMITER, [self::PREFIX, $this->encrypt($res->hash2Hex), $this->encrypt($salt), $res->versionId]);
    }

    public function IsBlindHashed($hash)
    {
        $hashArr = explode(self::DELIMITER, $hash);
        return (count($hashArr) == 4) ? true : false;
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
        $hashArr = explode(self::DELIMITER, $hash);
        if (count($hashArr) != 4) {
            return parent::validateHash($password, $hash);
        }

        // Get the pieces of the puzzle.
        list($T, $expectedHash2Hex, $salt, $tapLinkVersion) = $hashArr;

        $expectedHash2Hex = $this->decrypt($expectedHash2Hex);
        $salt = $this->decrypt($salt);

        // This is a TapLink Blind hash
        $res = $this->taplink->verifyPassword(hash_hmac(self::HASH_ALGORITHM, $password, $salt), $expectedHash2Hex, $tapLinkVersion);
        if ($res->error) {
            Mage::throwException($res->error);
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
    protected function _getRandomString($length, $chars = null)
    {
        $str = '';
        if (null === $chars) {
            $chars = 'abcdef0123456789';
        }

        mt_srand();
        for ($i = 0, $lc = strlen($chars) - 1; $i < $length; $i++) {
            $rand = mt_rand(0, $lc); // random integer from 0 to $lc
            $str .= $chars[$rand]; // random character in $chars
        }

        return $str;
    }
}
