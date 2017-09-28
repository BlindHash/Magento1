<?php
$ExternalLibPath = Mage::getModuleDir('', 'Jeremy_BlindHash') . DS . 'lib' . DS;

require_once $ExternalLibPath . 'Client.php';
require_once $ExternalLibPath . 'Response.php';

class Jeremy_BlindHash_Model_Encryption implements Jeremy_BlindHash_Model_Encryption_Interface
{

    /**
     * blindhash hash algorithm
     * default sha512
     *
     * @var string
     */
    protected $_hashAlgorithm;

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
        // TODO Hashing nad provide hashed string
    }

    /**
     * Validate hash against hashing method
     *
     * @param string $password
     * @param string $hash
     *
     * @return bool
     * @throws Mage_Core_Exception
     */
    public function validateHash($password, $hash)
    {
        // TO DO Validate hash with password and provide result 
    }

    /**
     * Get random string
     *
     * @param int         $length
     * @param null|string $chars
     * @return string
     */
    protected function _getRandomString($length, $chars = null)
    {
        $str = '';
        if (null === $chars) {
            $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
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
