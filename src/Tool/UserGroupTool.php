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

use Skyline\CMS\Security\UserSystem\Group;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\Security\Exception\SecurityException;
use TASoft\Util\PDO;

class UserGroupTool extends AbstractSecurityTool
{
    const SERVICE_NAME = 'groupTool';
    /** @var PDO */
    private $PDO;


    private $cachedGroups;
    private $groupNamesMap = [];

    /**
     * SecurityTool constructor.
     * @param $PDO
     */
    public function __construct($PDO)
    {
        $this->PDO = $PDO;
    }

    /**
     * Returns all available groups
     *
     * @return null|array        Keys as group id, values as group names or null, if no user logged
     */
    public function getGroups(): ?array {
        if(NULL === $this->cachedGroups) {
            $this->cachedGroups = [];
            foreach($this->PDO->select("SELECT id, name, description, options FROM SKY_GROUP") as $record) {
                $this->cachedGroups[ $record["id"] * 1 ] = new Group($record);
                $this->groupNamesMap[ strtolower($record["name"]) ] = $record["id"]*1;
            }
        }

        return $this->cachedGroups;
    }

    /**
     * @param string|int $group     A group  name or id
     * @return Group|null
     */
    public function getGroup($group): ?Group {
        $groups = $this->getGroups();
        if(!is_numeric($group))
            $group = $this->groupNamesMap[ strtolower((string)$group) ] ?? -1;
        return $groups[$group] ?? NULL;
    }

    /**
     * @param string $name
     * @param string|NULL $description
     * @param int $options
     * @return Group
     * @throws SecurityException
     */
    public function addGroup(string $name, string $description = NULL, int $options = 0): Group {
        if($this->PDO->selectOne("SELECT id FROM SKY_GROUP where name = ?", [$name])["id"] ?? false) {
            throw new SecurityException("Group $name already exists");
        }

        // TODO: later
    }
}