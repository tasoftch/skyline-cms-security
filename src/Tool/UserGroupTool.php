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

use Skyline\CMS\Security\Tool\Event\GroupEvent;
use Skyline\CMS\Security\UserSystem\Group;
use Skyline\Kernel\Service\SkylineServiceManager;
use Skyline\Security\Exception\SecurityException;
use TASoft\Util\PDO;
use Throwable;

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
     * @param $withEvents
     */
    public function __construct($PDO, $withEvents = true)
    {
        $this->PDO = $PDO;
        if(!$withEvents)
            $this->disableEvents();
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

        if($group instanceof Group)
            return $group;

        if(!is_numeric($group))
            $group = $this->groupNamesMap[ strtolower((string)$group) ] ?? -1;
        return $groups[$group] ?? NULL;
    }

    /**
     * @param Group $group
     * @param string $internalError
     * @internal
     */
    private function checkGroupIntegrity(Group $group, $internalError = "Group %s is internal and can not be changed") {
        $rid = $group->getId();
        $internal = Group::OPTION_INTERNAL;

        $result = $this->PDO->selectOne("SELECT CASE WHEN options & $internal > 0 THEN 1 ELSE 0 END AS internal FROM SKY_GROUP WHERE id = $rid")["internal"] ?? -1;
        if($result == -1)
            throw new SecurityException("No group %s in data base yet", 55, NULL, $group->getName());
        if($result == 1)
            throw new SecurityException($internalError, 56, NULL, $group->getName());
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

        $this->PDO->inject("INSERT INTO SKY_GROUP (name, description, options) VALUES (?, ?, ?)")->send([
            $name,
            $description,
            $options
        ]);
        $id = $this->PDO->lastInsertId("SKY_GROUP");

        $this->cachedGroups[ $id ] = $g = new Group([
            'id' => $id,
            'name' => $name,
            'description' => $description,
            'options' => $options
        ]);
        $this->groupNamesMap[ strtolower($name) ] = $id;

        if(!$this->disableEvents) {
            $e = new GroupEvent();
            $e->setGroup($g);
            SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_GROUP_ADD, $e, $g);
        }

        return $g;
    }

    public function updateGroup(Group $group, string $name = NULL, string $description = NULL, int $options = NULL) {
        $this->checkGroupIntegrity($group);

        if(count($this->PDO->selectOne("SELECT id FROM SKY_GROUP where name = ?", [$name])) > 0) {
            throw new SecurityException("Group $name already exists", 20);
        }

        $gid = $group->getId();

        $nam = $this->PDO->quote($name);
        $des = $this->PDO->quote($description);

        $list = [];
        if(NULL !== $name)
            $list[] = "name=$nam";
        if(NULL !== $description)
            $list[] = "description=$des";
        if(NULL !== $options)
            $list[] = "options=$options";
        if($list) {
            $list = implode(",", $list);
            $this->PDO->exec("UPDATE SKY_GROUP SET $list WHERE id = $gid");
        }

        if(!$this->disableEvents) {
            $e = new GroupEvent();
            $e->setGroup($group);
            SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_GROUP_UPDATE, $e, $group);
        }
    }

    public function removeGroup($group) {
        $group = $this->getGroup($group);
        $this->checkGroupIntegrity($group);

        if(!$this->disableEvents) {
            $ev = new GroupEvent();
            $ev->setGroup($group);
            SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_GROUP_REMOVE, $ev, $group);
        }

        try {
            $rid = $group->getId();

            $this->PDO->transaction(function() use ($rid) {
                $this->PDO->exec("DELETE FROM SKY_GROUP_ROLE WHERE groupid = $rid");
                $this->PDO->exec("DELETE FROM SKY_USER_GROUP WHERE groupid = $rid");
                $this->PDO->exec("DELETE FROM SKY_GROUP WHERE id = $rid");
            });
        } catch (Throwable $exception) {
            trigger_error($exception->getMessage(), E_USER_WARNING);
            return false;
        }
        return true;
    }
}