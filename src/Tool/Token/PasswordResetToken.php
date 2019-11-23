<?php
/**
 * BSD 3-Clause License
 *
 * Copyright (c) 2019, TASoft Applications
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

namespace Skyline\CMS\Security\Tool\Token;


use Skyline\Security\User\UserInterface;

class PasswordResetToken implements TokenInterface
{
    const ERROR_CODE_USER_NOT_FOUND = 404;
    const ERROR_CODE_USER_ALREADY_DEACTIVATED = 511;
    const ERROR_CODE_USER_DEACTIVATION_FAILED = 512;
    const ERROR_CODE_IMMUTABLE_PROVIDER = 299;

    /** @var bool */
    private $successful;
    /** @var UserInterface|null */
    private $user;
    /** @var string */
    private $token;
    /** @var int */
    private $errorCode;

    /**
     * PasswordResetToken constructor.
     * @param bool $successful
     * @param UserInterface|null $user
     * @param string $token
     */
    public function __construct(bool $successful, ?UserInterface $user, $token="", $errorCode = 0)
    {
        $this->successful = $successful;
        $this->user = $user;
        $this->token = $token;
        $this->errorCode = $errorCode;
    }


    /**
     * @return bool
     */
    public function isSuccessful(): bool
    {
        return $this->successful;
    }

    /**
     * @return UserInterface|null
     */
    public function getUser(): ?UserInterface
    {
        return $this->user;
    }

    /**
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * @return int
     */
    public function getErrorCode(): int
    {
        return $this->errorCode;
    }
}