<?php

namespace Skyline\CMS\Security\Exception;


use Skyline\Security\Exception\AuthorizationException;

class RequiredTokenException extends AuthorizationException
{
    private $token;

    /**
     * @return mixed
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @param mixed $token
     */
    public function setToken($token): void
    {
        $this->token = $token;
    }
}