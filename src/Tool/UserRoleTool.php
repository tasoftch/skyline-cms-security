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
use Skyline\CMS\Security\Tool\Event\NewRoleEvent;
use Skyline\CMS\Security\Tool\Event\UpdateRoleEvent;
use Skyline\CMS\Security\UserSystem\Role;
use Skyline\Kernel\Service\SkylineServiceManager;
use Skyline\Security\Exception\SecurityException;
use TASoft\Util\PDO;

class UserRoleTool extends AbstractSecurityTool
{
    use SecurityTrait;

    const SERVICE_NAME = 'roleTool';

    /** @var PDO */
    private $PDO;

    private $cachedRoleNames;
    private $roleIDNameMap;

    private $parentRoles;
    private $childRoles;


    /**
     * SecurityTool constructor.
     * @param $PDO
     */
    public function __construct($PDO)
    {
        $this->PDO = $PDO;
    }

    /**
     * Gets all available roles
     *
     * @return array    role id as key and role name as value
     */
    public function getRoles(): array {
        if(NULL === $this->cachedRoleNames) {
            if($this->PDO->getAttribute( PDO::ATTR_DRIVER_NAME ) == 'sqlite') {
                $gen = $this->PDO->select("SELECT DISTINCT
R1.id,
R1.description,
R1.options,
R1.parent,
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
LEFT JOIN SKY_ROLE AS R10 ON R6.id = R9.parent");
            } else {
                $gen = $this->PDO->select("SELECT DISTINCT
R1.id,
R1.description,
R1.options,
R1.parent,
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
LEFT JOIN SKY_ROLE AS R10 ON R6.id = R9.parent");
            }

            $parents = [];
            foreach($gen as $record) {
                $this->cachedRoleNames[ $record["id"]*1 ] = $r = new Role($record);
                $this->roleIDNameMap[ $record["role"] ] = $record["id"]*1;
                if($record["parent"]) {
                    $parents[] = (function() use ($r, $record) {
                        $this->parentRoles[ $r->getId() ] = $record["parent"] * 1;
                        $this->childRoles[ $record["parent"] * 1 ][] = $r->getId();
                    });
                }
            }

            foreach($parents as $parent)
                $parent();
        }
        return $this->cachedRoleNames;
    }

    /**
     * Returns the requested role
     *
     * @param string|int $role  A role name or id
     * @return Role|null
     */
    public function getRole($role): ?Role {
        $roles = $this->getRoles();
        if(!is_numeric($role)) {
            $role = $this->roleIDNameMap[ (string) $role ] ?? -1;
        }
        return $roles[$role] ?? NULL;
    }

    /**
     * Gets the parent of a role if available
     *
     * @param string|int $role  A role name or id
     * @return Role|null
     */
    public function getParent($role): ?Role {
        $role = $this->getRole($role);
        $pid = $this->parentRoles[ $role->getId() ] ?? NULL;
        if($pid !== NULL)
            return $this->cachedRoleNames[ $pid ] ?? NULL;
        return NULL;
    }

    /**
     * Gets the children of a role
     *
     * @param string|int $role  A role name or id
     * @return array|null
     */
    public function getChildren($role): ?array {
        $role = $this->getRole($role);
        if($children = $this->childRoles[ $role->getId() ] ?? NULL) {
            $ch = [];
            foreach($children as $child) {
                $ch[] = $this->cachedRoleNames[$child] ?? NULL;
            }
            return $ch;
        }
        return NULL;
    }

    /**
     * Adds a new role
     *
     * @param string $name
     * @param Role|NULL $parent
     * @param string|NULL $description
     * @param int $options
     * @return Role
     * @throws SecurityException
     */
    public function addRole(string $name, Role $parent = NULL, string $description = NULL, int $options = 0): Role {
        $name = strtoupper($name);

        $p = $parent ? $parent->getId() : 0;
        $rName = $parent ? ($parent->getRole() . ".$name") : $name;

        if($this->PDO->selectOne("SELECT id FROM SKY_ROLE WHERE parent = ? AND name = ? LIMIT 1", [$p, $name])["id"] ?? 0) {
            throw new SecurityException("Role %s already exists", 20, NULL, $rName);
        }

        // User can not add internal roles
        $options &= ~Role::OPTION_INTERNAL;
        $this->PDO->inject("INSERT INTO SKY_ROLE (name, description, parent, options) VALUES (?, ?, $p, $options)")->send([
            $name,
            $description ?: ""
        ]);
        $id = $this->PDO->lastInsertId();
        $r = $this->cachedRoleNames[ $id ] = new Role([
            "role" => $rName,
            'id' => $id,
            'description' => $description ?: "",
            'options' => $options
        ]);

        $this->roleIDNameMap[ $rName ] = $id;
        if($parent) {
            $this->parentRoles[ $id ] = $parent->getId();
            $this->childRoles[ $parent->getId() ][] = $id;
        }



        if(!$this->disableEvents) {
            $ev = new NewRoleEvent();
            $ev->setRole($r);
            SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_ADD_ROLE, $ev);
        }


        return $r;
    }

    /**
     * @param Role $role
     * @param string $internalError
     * @internal
     */
    private function checkRoleIntegrity(Role $role, $internalError = "Role %s is internal and can not be changed") {
        $rid = $role->getId();
        $internal = Role::OPTION_INTERNAL;

        $result = $this->PDO->selectOne("SELECT CASE WHEN options & $internal > 0 THEN 1 ELSE 0 END AS internal FROM SKY_ROLE WHERE id = $rid")["internal"] ?? -1;
        if($result == -1)
            throw new SecurityException("No role %s in data base yet", 55, NULL, $role->getRole());
        if($result == 1)
            throw new SecurityException($internalError, 56, NULL, $role->getRole());
    }

    /**
     * Removes a role from data base.
     * Please note, that this action will also remove all relationships for the passed role.
     * That means the following actions are done:
     *
     * - Trigger the remove role event (if enabled)
     * - Removes assigned role from groups
     * - Remove assigned role from users
     * - Remove role
     *
     * @param Role $role
     * @return bool
     * @throws SecurityException
     */
    public function removeRole(Role $role) {
        $this->checkRoleIntegrity($role, "Role %s is internal and can not be removed");

        if(!$this->disableEvents) {
            $ev = new NewRoleEvent();
            $ev->setRole($role);
            SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_REMOVE_ROLE, $ev);
        }

        try {
            $rid = $role->getId();

            $this->PDO->transaction(function() use ($rid) {
                $self = $this;
                /** @var PDO $self */
                $self->exec("DELETE FROM SKY_GROUP_ROLE WHERE role = $rid");
                $self->exec("DELETE FROM SKY_USER_ROLE WHERE role = $rid");
                $self->exec("DELETE FROM SKY_ROLE WHERE id = $rid");
            });
        } catch (\Throwable $exception) {
            trigger_error($exception->getMessage(), E_USER_WARNING);
            return false;
        }
        return true;
    }

    /**
     * Updates the passed role to have new properties.
     *
     * @param Role $role
     * @param string|NULL $newName          A new name if not NULL
     * @param string|NULL $newDescription   A new description if not NULL
     * @param int|NULL $newOptions          New options if not NULL
     * @return bool
     */
    public function updateRole(Role $role, string $newName = NULL, string $newDescription = NULL, int $newOptions = NULL) {
        $this->checkRoleIntegrity($role, 'Role %s is internal and can not be changed');

        if($newName) {
            $newName = strtoupper(
                $newName
            );

            $p = $this->parentRoles[ $role->getId() ] ?? 0;

            if($this->PDO->selectOne("SELECT id FROM SKY_ROLE WHERE parent = ? AND name = ? LIMIT 1", [$p, $newName])["id"] ?? 0) {
                $p = $this->getParent($role);
                throw new SecurityException("Role %s already exists", 20, NULL, $p ? ($p->getRole() . ".$newName") : $newName);
            }
        }

        if(NULL !== $newOptions) {
            $newOptions &= ~Role::OPTION_INTERNAL;
        }

        if(!$this->disableEvents) {
            $ev = new UpdateRoleEvent();
            $ev->setRole($role);
            $ev->setOptions($newOptions);
            $ev->setDescription($newDescription);
            $ev->setName($newName);
            SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_UPDATE_ROLE, $ev);
        }

        try {
            $PDO = $this->PDO;
            $rid = $role->getId();

            $this->PDO->transaction(function() use ($PDO, $newName, $newDescription, $newOptions, $rid) {
                if($newName)
                    $PDO->inject("UPDATE SKY_ROLE SET name = ? WHERE id = $rid")->send([$newName]);
                if(NULL !== $newDescription)
                    $PDO->inject("UPDATE SKY_ROLE SET description = ? WHERE id = $rid")->send([$newDescription]);
                if(NULL !== $newOptions)
                    $PDO->inject("UPDATE SKY_ROLE SET options = ? WHERE id = $rid")->send([$newOptions]);
            });

            (function() use ($role, $newDescription, $newOptions) {
                if(NULL !== $newDescription)
                    $role->description = $newDescription;
                if(NULL !== $newOptions)
                    $role->options = $newOptions;
            })->bindTo($role, Role::class)();
            if(NULL !== $newName) {
                $data = explode(".", $role->getRole());
                array_pop($data);
                $data[] = $newName;
                $newRole = implode(".", $data);

                unset($this->roleIDNameMap[ $role->getRole() ]);
                $this->roleIDNameMap[ $newRole ] = $role->getId();

                (function() use ($role, $newRole) {
                    $role->role = $newRole;
                })->bindTo($role, \Skyline\Security\Role\Role::class)();
            }

            return true;
        } catch (\Throwable $exception) {
            trigger_error($exception->getMessage(), E_USER_WARNING);
            return false;
        }
    }

    /**
     * Changes the parent of a role.
     *
     * @param Role $role
     * @param Role|NULL $parent
     * @param bool $updateHierarchie        If set to true, the whole cache gets removed and is loaded new the next time roles are required.
     * @return bool
     */
    public function updateRoleParent(Role $role, Role $parent = NULL, bool $updateHierarchie = false) {
        $this->checkRoleIntegrity($role, 'Role %s is internal and can not be changed');
        $p = $this->getParent($role);

        $rid = $role->getId();

        if($parent && ($p === NULL || $p->getId() != $parent->getId())) {
            if($parent->getOptions() & Role::OPTION_FINAL)
                throw new SecurityException("Role %s is final", 58, NULL, $parent->getRole());

            if(!$this->disableEvents) {
                $ev = new UpdateRoleEvent();
                $ev->setRole($role);
                $ev->setParentRole($parent);
                SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_UPDATE_ROLE, $ev);
            }

            $pid = $parent->getId();
            $this->PDO->exec("UPDATE SKY_ROLE SET parent = $pid WHERE id = $rid");
            if($updateHierarchie)
                $this->cachedRoleNames = $this->roleIDNameMap = $this->parentRoles = $this->childRoles = NULL;
            return true;
        } elseif($p) {

            if(!$this->disableEvents) {
                $ev = new UpdateRoleEvent();
                $ev->setRole($role);
                $ev->setParentRole(NULL);
                SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_UPDATE_ROLE, $ev);
            }

            $this->PDO->exec("UPDATE SKY_ROLE SET parent = 0 WHERE id = $rid");
            if($updateHierarchie)
                $this->cachedRoleNames = $this->roleIDNameMap = $this->parentRoles = $this->childRoles = NULL;
            return true;
        }

        return false;
    }
}