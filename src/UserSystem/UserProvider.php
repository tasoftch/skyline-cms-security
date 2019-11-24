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


use Skyline\CMS\Security\Tool\UserRoleTool;
use Skyline\Security\User\Provider\MutableUserProviderInterface;
use Skyline\Security\User\Provider\UserProviderAwareInterface;
use Skyline\Security\User\Provider\UserProviderInterface;
use Skyline\Security\User\UserInterface;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

class UserProvider implements UserProviderInterface, UserProviderAwareInterface, MutableUserProviderInterface
{
    /** @var PDO */
    private $PDO;

    /**
     * UserProvider constructor.
     * @param PDO $PDO
     */
    public function __construct(PDO $PDO)
    {
        $this->PDO = $PDO;
    }


    public function setOptions(int $options, UserInterface $forUser)
    {
        $this->PDO->inject("UPDATE SKY_USER SET options = ? WHERE username = ?")->send([$options, $forUser->getUsername()]);
        return true;
    }

    public function setCredentials(string $credentials, UserInterface $forUser, $options)
    {
        $this->PDO->inject("UPDATE SKY_USER SET credentials = ? WHERE username = ?")->send([$credentials, $forUser->getUsername()]);
        return true;
    }

    public function getUsernames(): array
    {
        $names = [];
        foreach($this->PDO->select("SELECT id, username FROM SKY_USER ORDER BY username") as $row) {
            $names[ $row["id"] ] = $row["username"];
        }
        return $names;
    }

    public function loadUserWithToken(string $token): ?UserInterface
    {
        $withMailOption = User::OPTION_CAN_LOGIN_WITH_MAIL;

        $user = $this->PDO->selectOne("SELECT * FROM SKY_USER WHERE id = ? OR username = ? OR (options & $withMailOption AND email = ?)", [
            $token,
            $token,
            $token
        ]);

        if($user) {
            $roles = [];
            $uid = $user["id"];

            /** @var UserRoleTool $rTool */
            $rTool = ServiceManager::generalServiceManager()->get(UserRoleTool::SERVICE_NAME);

            foreach($this->PDO->select("SELECT DISTINCT
    SKY_ROLE.id AS role
FROM SKY_ROLE
         LEFT JOIN SKY_GROUP_ROLE ON SKY_GROUP_ROLE.role = SKY_ROLE.id
         LEFT JOIN SKY_USER_GROUP ON SKY_GROUP_ROLE.`groupid` = SKY_USER_GROUP.`groupid`
         LEFT JOIN SKY_USER_ROLE ON SKY_USER_ROLE.role = SKY_ROLE.id
WHERE SKY_USER_ROLE.user = $uid OR SKY_USER_GROUP.user = $uid") as $record) {
                    $roles[] = $rTool->getRole( $record["role"] * 1);
                }


            return new User($user, $roles);
        }
        return NULL;
    }
}