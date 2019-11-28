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

namespace Skyline\CMS\Security\UserSystem;


use Skyline\PDO\PDOResourceInterface;
use Skyline\Security\User\AdvancedUser;

class User extends AdvancedUser implements PDOResourceInterface
{
    const OPTION_CAN_LOGIN_WITH_MAIL = 1<<3;
    const OPTION_INVALIDATE_SESSION = 1<<4;


    /** @var int  */
    private $id;

    /** @var string */
    private $name;
    /** @var string */
    private $surname;
    /** @var string */
    private $email;

    public function __construct(array $dataBaseRecord, array $roles)
    {
        parent::__construct($dataBaseRecord["username"], $dataBaseRecord["credentials"], $roles, $dataBaseRecord["options"] * 1);

        $this->id = $dataBaseRecord["id"] * 1;
        $this->name = $dataBaseRecord["prename"];
        $this->surname = $dataBaseRecord["surname"];
        $this->email = $dataBaseRecord["email"];
    }

    /**
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * @return string
     */
    public function getSurname(): string
    {
        return $this->surname;
    }

    /**
     * Makes a full name
     * @return string
     */
    public function getFullName() {
        $pre = $this->getName();
        $sur = $this->getSurname();

        if($pre && $sur) {
            return "$pre $sur";
        } elseif ($sur)
            return $sur;
        elseif ($pre){
            return $pre;
        }
        return ucfirst( $this->getUsername() );
    }
}