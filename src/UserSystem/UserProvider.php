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


use Skyline\Security\User\Provider\MutableUserProviderInterface;
use Skyline\Security\User\Provider\UserProviderAwareInterface;
use Skyline\Security\User\Provider\UserProviderInterface;
use Skyline\Security\User\UserInterface;
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

    public function getMemberShip($username): array {
        $groups = [];
        foreach($this->PDO->select("SELECT
    SKY_GROUP.id, name
FROM SKY_GROUP
         JOIN SKY_USER_GROUP ON groupid = id
        JOIN SKY_USER ON user = SKY_USER.id
WHERE username = ?", [$username]) as $group) {
            $groups[ $group["id"] * 1 ] = $group["name"];
        }
        return $groups;
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



            if($this->PDO->getAttribute(PDO::ATTR_DRIVER_NAME) == 'sqlite') {
                foreach($this->PDO->select("SELECT DISTINCT 
CASE
      WHEN R10.id IS NOT NULL
      THEN R10.name || '.' || R9.name || '.' || R8.name || '.' || R7.name || '.' || R6.name || '.' || R5.name || '.' || R4.name || '.' || R3.name || '.' || R2.name || '.' || R1.name

      WHEN R9.id IS NOT NULL
      THEN R9.name || '.' || R8.name || '.' || R7.name || '.' || R6.name || '.' || R5.name || '.' || R4.name || '.' || R3.name || '.' || R2.name || '.' || R1.name

      WHEN R8.id IS NOT NULL
      THEN R8.name || '.' || R7.name || '.' || R6.name || '.' || R5.name || '.' || R4.name || '.' || R3.name || '.' || R2.name || '.' || R1.name

      WHEN R7.id IS NOT NULL
      THEN R7.name || '.' || R6.name || '.' || R5.name || '.' || R4.name || '.' || R3.name || '.' || R2.name || '.' || R1.name

      WHEN R6.id IS NOT NULL
      THEN R6.name || '.' || R5.name || '.' || R4.name || '.' || R3.name || '.' || R2.name || '.' || R1.name

      WHEN R5.id IS NOT NULL
      THEN R5.name || '.' || R4.name || '.' || R3.name || '.' || R2.name || '.' || R1.name

      WHEN R4.id IS NOT NULL
      THEN R4.name || '.' || R3.name || '.' || R2.name || '.' || R1.name

      WHEN R3.id IS NOT NULL
      THEN R3.name || '.' || R2.name || '.' || R1.name

      WHEN R2.id IS NOT NULL
      THEN R2.name || '.' || R1.name

      ELSE R1.name
END as role
FROM SKY_ROLE AS R1
LEFT JOIN SKY_ROLE AS R2 ON R2.id = R1.parent
LEFT JOIN SKY_ROLE AS R3 ON R3.id = R2.parent
LEFT JOIN SKY_ROLE AS R4 ON R4.id = R3.parent
LEFT JOIN SKY_ROLE AS R5 ON R5.id = R4.parent
LEFT JOIN SKY_ROLE AS R6 ON R6.id = R5.parent
LEFT JOIN SKY_ROLE AS R7 ON R6.id = R6.parent
LEFT JOIN SKY_ROLE AS R8 ON R6.id = R7.parent
LEFT JOIN SKY_ROLE AS R9 ON R6.id = R8.parent
LEFT JOIN SKY_ROLE AS R10 ON R6.id = R9.parent

LEFT JOIN SKY_GROUP_ROLE ON SKY_GROUP_ROLE.role = R1.id
LEFT JOIN SKY_USER_GROUP ON SKY_GROUP_ROLE.`groupid` = SKY_USER_GROUP.`groupid`
LEFT JOIN SKY_USER_ROLE ON SKY_USER_ROLE.role = R1.id
WHERE SKY_USER_ROLE.user = $uid OR SKY_USER_GROUP.user = $uid
ORDER BY role") as $record) {
                    $roles[] = $record["role"];
                }
            } else {
                foreach($this->PDO->select("SELECT DISTINCT 
CASE
      WHEN R10.id IS NOT NULL
      THEN CONCAT(R10.name, '.', R9.name, '.', R8.name, '.', R7.name, '.', R6.name, '.', R5.name, '.', R4.name, '.', R3.name, '.', R2.name, '.', R1.name)

      WHEN R9.id IS NOT NULL
      THEN CONCAT(R9.name, '.', R8.name, '.', R7.name, '.', R6.name, '.', R5.name, '.', R4.name, '.', R3.name, '.', R2.name, '.', R1.name)

      WHEN R8.id IS NOT NULL
      THEN CONCAT(R8.name, '.', R7.name, '.', R6.name, '.', R5.name, '.', R4.name, '.', R3.name, '.', R2.name, '.', R1.name)

      WHEN R7.id IS NOT NULL
      THEN CONCAT(R7.name, '.', R6.name, '.', R5.name, '.', R4.name, '.', R3.name, '.', R2.name, '.', R1.name)

      WHEN R6.id IS NOT NULL
      THEN CONCAT(R6.name, '.', R5.name, '.', R4.name, '.', R3.name, '.', R2.name, '.', R1.name)

      WHEN R5.id IS NOT NULL
      THEN CONCAT(R5.name, '.', R4.name, '.', R3.name, '.', R2.name, '.', R1.name)

      WHEN R4.id IS NOT NULL
      THEN CONCAT(R4.name, '.', R3.name, '.', R2.name, '.', R1.name)

      WHEN R3.id IS NOT NULL
      THEN CONCAT(R3.name, '.', R2.name, '.', R1.name)

      WHEN R2.id IS NOT NULL
      THEN CONCAT(R2.name, '.', R1.name)

      ELSE R1.name
END as role
FROM SKY_ROLE AS R1
LEFT JOIN SKY_ROLE AS R2 ON R2.id = R1.parent
LEFT JOIN SKY_ROLE AS R3 ON R3.id = R2.parent
LEFT JOIN SKY_ROLE AS R4 ON R4.id = R3.parent
LEFT JOIN SKY_ROLE AS R5 ON R5.id = R4.parent
LEFT JOIN SKY_ROLE AS R6 ON R6.id = R5.parent
LEFT JOIN SKY_ROLE AS R7 ON R6.id = R6.parent
LEFT JOIN SKY_ROLE AS R8 ON R6.id = R7.parent
LEFT JOIN SKY_ROLE AS R9 ON R6.id = R8.parent
LEFT JOIN SKY_ROLE AS R10 ON R6.id = R9.parent

LEFT JOIN SKY_GROUP_ROLE ON SKY_GROUP_ROLE.role = R1.id
LEFT JOIN SKY_USER_GROUP ON SKY_GROUP_ROLE.`groupid` = SKY_USER_GROUP.`groupid`
LEFT JOIN SKY_USER_ROLE ON SKY_USER_ROLE.role = R1.id
WHERE SKY_USER_ROLE.user = $uid OR SKY_USER_GROUP.user = $uid
ORDER BY role") as $record) {
                    $roles[] = $record["role"];
                }
            }


            return new User($user, $roles);
        }
        return NULL;
    }
}