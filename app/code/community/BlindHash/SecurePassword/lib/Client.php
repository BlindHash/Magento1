<?php
error_reporting(E_ALL ^ E_WARNING); 

//$ExternalLibPath = Mage::getModuleDir('', 'BlindHash_SecurePassword') . DS . 'lib' . DS;
//include_once $ExternalLibPath . "sodium_compat/sodium-compat.phar";
require 'sodium_compat' . DS . 'random_compat.phar';
require 'sodium_compat' . DS . 'autoload-fast.php';

class Client
{

    public $appID;
    public $userAgent;
    public $servers;
    public static $hashAlgorithm = 'sha512';
    public static $defaultServer = 'api.taplink.co';

    function __construct($appID)
    {
        $this->appID = $appID;
        $this->userAgent = 'TapLink/1.0 php/' . phpversion();
        $this->servers = [self::$defaultServer];
    }

    public function getSalt($hash1Hex, $versionID = null)
    {
        return $this->get(sprintf('%s/%s/%s', $this->appID, $hash1Hex, $versionID ? : ''));
    }

    public function verifyPassword($hash1Hex, $hash2ExpectedHex, $versionId = null)
    {
        $res = $this->getSalt($hash1Hex, $versionId);
        if (!$res->err) {
            $res->hash2Hex = hash_hmac(self::$hashAlgorithm, hex2bin($hash1Hex), hex2bin($res->salt2Hex));
        }
        $res->matched = !$res->err && $res->hash2Hex === $hash2ExpectedHex;
        if ($res->matched && $res->newVersionId && $res->newSalt2Hex) {
            $res->newHash2Hex = hash_hmac(self::$hashAlgorithm, hex2bin($hash1Hex), hex2bin($res->newSalt2Hex));
        }
        return $res;
    }

    public function newPassword($hash1Hex)
    {
        $res = $this->getSalt($hash1Hex);
        if (!$res->err) {
            $res->hash2Hex = hash_hmac(self::$hashAlgorithm, hex2bin($hash1Hex), hex2bin($res->salt2Hex));
        }
        return $res;
    }

    private function getServer($attempts = 0)
    {
        if (empty($this->servers)) {
            return self::$defaultServer;
        }
        if (!$attempts) {
            return $this->servers[0];
        }
        return $this->servers[$attempts % count($this->servers)];
    }

    private function makeURL($url, $attempts = 0)
    {
        return sprintf('https://%s/%s', trim($this->getServer($attempts), '/'), ltrim($url, '/'));
    }

    private function get($url)
    {
        $ch = curl_init($this->makeURL($url));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);        
        $verifyer = ($this->isLocalMachine()) ? false : true;
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verifyer);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'User-Agent: ' . $this->userAgent,
            'Accept: application/json',
        ));
        $res = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($status !== 200) {
            return new Response(['err' => true, 'errCode' => curl_errno($ch), 'errMsg' => curl_error($ch)]);
        }
        return new Response(json_decode($res, true));
    }

    public function isLocalMachine()
    {
        $whitelist = array(
            '127.0.0.1',
            '::1'
        );
        return (in_array($_SERVER['REMOTE_ADDR'], $whitelist)) ? true : false;
    }

    public function verifyAppId()
    {
        $res =  $this->get(sprintf('%s', $this->appID));
        return (!$res->err) ? true : false;
    }

    public function getPublicKey()
    {
        $ch = curl_init($this->makeURL($this->appID));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $verifyer = ($this->isLocalMachine()) ? false : true;
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verifyer);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'User-Agent: ' . $this->userAgent,
            'Accept: application/json',
        ));
        $res = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($status !== 200) {
            return;
        }
        $res = json_decode($res, true);
        if (isset($res['publicKey']))
            return $res['publicKey'];
        else
            return;
    }

    public function encrypt($publicKeyHex, $hashHex)
    {
        if (!function_exists('\Sodium\crypto_box_seal')) {
            return $hashHex;
        }

        $crypt = \Sodium\crypto_box_seal(hex2bin($hashHex), hex2bin($publicKeyHex));
        return bin2hex($crypt);
    }

    public function decrypt($publicKeyHex, $privateKeyHex, $cryptHex)
    {
        if (!function_exists('\Sodium\crypto_box_seal')) {
            return $cryptHex;
        }

        $keypair = hex2bin($privateKeyHex . $publicKeyHex);
        $decrypt = \Sodium\crypto_box_seal_open(hex2bin($cryptHex), $keypair);
        return bin2hex($decrypt);
    }

    public function encryptTest()
    {
        if (!function_exists('\Sodium\crypto_box_seal')) {
            Mage::log('encryptTest:Function does not exist');
            return false;
        }

        try {
            $message = "This is a test.";
            $keypair = hex2bin(
                '15b36cb00213373fb3fb03958fb0cc0012ecaca112fd249d3cf0961e311caac9' .
                'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
            );
            $publickey = hex2bin(
                'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
            );
            $crypt = \Sodium\crypto_box_seal($message, $publickey);
            $decrypt = \Sodium\crypto_box_seal_open($crypt, $keypair);
            $res = strcmp($message, $decrypt) === 0;
            // Mage::log('encryptTest Result:' . ($res ? 'True' : 'False'));
            return $res;
        } catch (Exception $e) {
            Mage::log('encryptTest Exception');
            return false;
        }
    }
}
