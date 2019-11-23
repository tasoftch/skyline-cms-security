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

namespace Skyline\CMS\Security\Tool;


use Skyline\CMS\Security\SecurityTrait;
use Skyline\CMS\Security\UserSystem\User;
use TASoft\Util\PDO;

class UserGroupTool
{
    use SecurityTrait;

    const SERVICE_NAME = 'groupTool';
    /** @var PDO */
    private $PDO;


    private $cachedGroups;
    private $cachedDescriptions = [];
    private $cachedInternal = [];

    /**
     * SecurityTool constructor.
     * @param $PDO
     */
    public function __construct($PDO)
    {
        $this->PDO = $PDO;
    }

    /**
     * Returns all groups the current logged user is member of
     *
     * @return null|array        Keys as group id, values as group names or null, if no user logged
     */
    public function getGroups(): ?array {
        if($user = $this->getUser()) {
            if(NULL === $this->cachedGroups) {
                $this->cachedGroups = [];

                if($user instanceof User) {
                    $uid = $user->getId();
                    $gen = $this->PDO->select("SELECT
   groupid as id,
   name
FROM SKY_USER_GROUP
JOIN SKY_GROUP ON groupid = id
WHERE user = $uid");
                } else {
                    $gen = $this->PDO->select("SELECT
   SKY_GROUP.id,
   name
FROM SKY_USER
JOIN SKY_USER_GROUP ON user = id
JOIN SKY_GROUP ON groupid = SKY_GROUP.id
WHERE username = ?", [ $user->getUsername() ]);
                }

                foreach($gen as $record) {
                    $this->cachedGroups[ $record["id"] * 1 ] = $record["name"];
                }
            }

            return $this->cachedGroups;
        }
        return NULL;
    }

    /**
     * Gets the description of a group
     *
     * @param int|string $group     groupid or group name
     * @return string|null
     */
    public function getDescription($group) {
        if(!isset($this->cachedDescriptions[$group])) {
            $this->cachedDescriptions[$group] = "";

            foreach($this->PDO->select("SELECT
description, name, id
FROM SKY_GROUP
WHERE id = ? OR name = ?
LIMIT 1", [$group, $group]) as $record) {
                $this->cachedDescriptions[ $record["id"]*1 ] = $this->cachedDescriptions[ $record["name"] ] = $record[ "description" ];
            }
        }
        return $this->cachedDescriptions[$group];
    }

    /**
     * Returns true, if the group is an internal group of Skyline CMS
     *
     * @param int|string $group     groupid or group name
     * @return bool
     */
    public function isInternal($group): bool {
        if(!isset($this->cachedInternal[$group])) {
            $this->cachedInternal[$group] = false;

            foreach($this->PDO->select("SELECT
internal, name, id
FROM SKY_GROUP
WHERE id = ? OR name = ?
LIMIT 1", [$group, $group]) as $record) {
                $this->cachedInternal[ $record["id"]*1 ] = $this->cachedInternal[ $record["name"] ] = $record[ "internal" ] ? true : false;
            }
        }
        return $this->cachedInternal[$group];
    }


}