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

use Skyline\CMS\Security\UserSystem\Role;
use TASoft\Util\PDO;

class UserRoleTool extends AbstractSecurityTool
{
    const SERVICE_NAME = 'roleTool';

    /** @var PDO */
    protected $PDO;

	protected $cachedRoleNames;
	protected $roleIDNameMap;

	protected $parentRoles;
	protected $childRoles;

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
	 * Yields all children recursively.
	 *
	 * @param $role
	 * @return \Generator
	 */
    public function yieldAllChildren($role) {
    	if($children = $this->getChildren($role)) {
    		foreach($children as $child) {
				if(yield $child)
					continue;

    			yield from $this->yieldAllChildren($child);
			}
		}
	}
}