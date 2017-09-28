<?php

interface Jeremy_BlindHash_Model_Encryption_Interface
{

    /**
     * validate the password against the hash
     *
     * @param $password password
     * @param $hash hash to validate against
     *
     * @return boolean
     */
    public function validateHash($password, $hash);

    /**
     * get the password hashed with the passed salt
     *
     * @param  string $password the users password
     * @param bool|string $salt if false, then a salt will be
     * generated, if string, the string will be used
     *
     * @return string the hashed password with the salt
     */
    public function getHash($password, $salt = false);
}
