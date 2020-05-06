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
use Skyline\Security\Role\RoleInterface;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

class UserGroupTool extends AbstractSecurityTool
{
    const SERVICE_NAME = 'groupTool';
    /** @var PDO */
    protected $PDO;


    protected $cachedGroups;
    protected $groupNamesMap = [];

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
	 * Gets a list of all user ids which are member of the given group.
	 * It returns a list with user ids as keys and user names as values
	 *
	 * @param $group
	 * @return int[]|null
	 */
	public function getUsers($group): ?array {
    	if($group = $this->getGroup($group)) {
    		$gid = $group->getId();
    		$users = [];
    		foreach($this->PDO->select("SELECT id, username FROM SKY_USER_GROUP JOIN SKY_USER ON id = user WHERE groupid = $gid ORDER BY username") as $record) {
				$users[ $record['id'] ] = $record['username'];
			}
    		return $users;
		}
    	return NULL;
	}

	/**
	 * Gets all roles assigned to a given group
	 *
	 * @param int|string|Group $group
	 * @return RoleInterface[]|null
	 */
	public function getRoles($group): ?array {
    	if($group = $this->getGroup($group)) {
    		$rt = ServiceManager::generalServiceManager()->get(UserRoleTool::SERVICE_NAME);
    		if($rt instanceof UserRoleTool) {
    			$roles = [];
    			foreach($this->PDO->select("SELECT role FROM SKY_GROUP_ROLE WHERE groupid = ?", [$group->getId()]) as $record) {
    				if($r = $rt->getRole($record["role"]))
    					$roles[$r->getId()] = $r;
				}
    			return $roles;
			}
		}
    	return NULL;
	}
}