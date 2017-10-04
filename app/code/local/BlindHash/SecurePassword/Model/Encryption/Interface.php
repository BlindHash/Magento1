<?php

interface BlindHash_SecurePassword_Model_Encryption_Interface
{

    /**
     * Validate hash against hashing method (with or without salt)
     *
     * @param string $password
     * @param string $hash
     * @return bool
     * @throws \Exception
     */
    public function validateHash($password, $hash);

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
    public function getHash($plaintext, $salt = false);
}
