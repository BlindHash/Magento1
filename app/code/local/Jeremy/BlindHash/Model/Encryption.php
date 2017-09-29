<?php
$ExternalLibPath = Mage::getModuleDir('', 'Jeremy_BlindHash') . DS . 'lib' . DS;

require_once $ExternalLibPath . 'Client.php';
require_once $ExternalLibPath . 'Response.php';

class Jeremy_BlindHash_Model_Encryption extends Mage_Core_Model_Encryption implements Jeremy_BlindHash_Model_Encryption_Interface
{

    const DEFAULT_SALT_LENGTH = 64;
    const HASH_VERSION_SHA512 = 3;
    const HASH_VERSION_LATEST = 3;
    const DELIMITER = '$';

    /**
     * @var array map of hash versions
     */
    private $hashVersionMap = [
        parent::HASH_VERSION_MD5 => 'md5',
        parent::HASH_VERSION_SHA256 => 'sha256',
        self::HASH_VERSION_SHA512 => 'sha512',
    ];

    /**
     * blindhash hash algorithm
     * default sha512
     *
     * @var string
     */
    protected $_hashAlgorithm;

    public function __construct()
    {
        //Get Api key from System Config
        $appId = Mage::getStoreConfig('jeremy/blindhash/api_key');
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
    public function getHash($password, $salt = false, $version = self::HASH_VERSION_LATEST)
    {
        // TODO Hashing and provide hashed string
        if ($salt === false) {
            return $this->hash($password, $version);
        }
        if ($salt === true) {
            $salt = self::DEFAULT_SALT_LENGTH;
        }
        if (is_integer($salt)) {
            $salt = $this->_getRandomString($salt);
        }
        // The hash to send to TapLink is the SHA512-HMAC(salt, password)
        $res = $this->taplink->newPassword(hash_hmac(self::HASH_VERSION_LATEST, $password, $salt));
        if ($res->error) {
            Mage::throwException($res->error);
        }

        // TODO handle potential version upgrades from the API.
        // The format is <hash2hex>:<salt>:<hash_version>:<taplink.version>
        return implode(self::DELIMITER, [$res->hash2hex, $salt, self::HASH_VERSION_LATEST, $res->versionId]);
    }

    public function hash($data, $version = self::HASH_VERSION_LATEST)
    {
        return hash($this->hashVersionMap[$version], $data);
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
        // TO DO Validate hash with password and provide result 
        // Get the pieces of the puzzle.
        list($expectedHash2Hex, $salt, $version, $tapLinkVersion) = explode(self::DELIMITER, $hash);
        $version = (int) $version;
        if ($version <= 1) {
            // TODO Upgrade to blind hashes.
            return parent::validateHash($password, $hash);
        }
        // This is a TapLink Blind hash
        $res = $this->taplink->verifyPassword(hash_hmac('sha512', $salt, $password), $expectedHash2Hex, $tapLinkVersion);
        if ($res->error) {
            throw new TapLinkException($res->error);
        }
        // TODO upgrade of TapLink version
        if ($res->newVersionId) {
            
        }
        return $res->matched;
    }

    /**
     * Validate hashing algorithm version
     *
     * @param string $hash
     * @param bool $validateCount
     * @return bool
     */
    public function validateHashVersion($hash, $validateCount = false)
    {
        list(,, $version, $tapLinkVersion) = explode(parent::DELIMITER, $hash);
        $version = (int) $version;
        // Magento hash version, not blind hash, so let parent handle.
        if ($version <= 1) {
            return parent::validateHashVersion($hash, $validateCount);
        }
        // Return whether version and taplink version are okay
        return $version === self::CURRENT_VERSION && (int) $tapLinkVersion <= 3;
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

        if (function_exists('openssl_random_pseudo_bytes')) {
            // use openssl lib if it is installed
            for ($i = 0, $lc = strlen($chars) - 1; $i < $length; $i++) {
                $bytes = openssl_random_pseudo_bytes(PHP_INT_SIZE);
                $hex = bin2hex($bytes); // hex() doubles the length of the string
                $rand = abs(hexdec($hex) % $lc); // random integer from 0 to $lc
                $str .= $chars[$rand]; // random character in $chars
            }
        } elseif ($fp = @fopen('/dev/urandom', 'rb')) {
            // attempt to use /dev/urandom if it exists but openssl isn't available
            for ($i = 0, $lc = strlen($chars) - 1; $i < $length; $i++) {
                $bytes = @fread($fp, PHP_INT_SIZE);
                $hex = bin2hex($bytes); // hex() doubles the length of the string
                $rand = abs(hexdec($hex) % $lc); // random integer from 0 to $lc
                $str .= $chars[$rand]; // random character in $chars
            }
            fclose($fp);
        } else {
            // fallback to mt_rand() if all else fails
            mt_srand();
            for ($i = 0, $lc = strlen($chars) - 1; $i < $length; $i++) {
                $rand = mt_rand(0, $lc); // random integer from 0 to $lc
                $str .= $chars[$rand]; // random character in $chars
            }
        }

        return $str;
    }
}
