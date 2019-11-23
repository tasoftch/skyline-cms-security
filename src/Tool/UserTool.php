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

use Skyline\CMS\Security\Identity\IdentityInstaller;
use Skyline\CMS\Security\SecurityTrait;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Role\RoleInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Response;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

/**
 * The user tool allows your application several actions around users, groups and roles.
 * @package Skyline\CMS\Security
 */
class UserTool
{
    const SERVICE_NAME = 'userTool';
    use SecurityTrait {
        hasIdentity as _t_hasIdentity;
        getIdentity as _t_getIdentity;
        requireIdentity as _t_requireIdentity;

        hasUser as _t_hasUser;
        getUser as _t_getUser;
        requireUser as _t_requireUser;
    }

    /** @var PDO */
    private $PDO;

    private $cachedUserRoles;

    /**
     * SecurityTool constructor.
     * @param $PDO
     */
    public function __construct($PDO)
    {
        $this->PDO = $PDO;
    }

    /**
     * @inheritDoc
     * Forward trait method
     */
    public function hasIdentity($minimalReliability = 0): bool
    {
        return $this->_t_hasIdentity($minimalReliability);
    }

    /**
     * @inheritDoc
     * Forward trait method
     */
    public function getIdentity($minimalReliability = 0, IdentityInterface &$minimalFound = NULL): ?IdentityInterface
    {
        return $this->_t_getIdentity($minimalReliability, $minimalFound);
    }

    /**
     * @inheritDoc
     * Forward trait method
     */
    public function requireIdentity($minimalReliability = 0): IdentityInterface
    {
        return $this->_t_requireIdentity($minimalReliability);
    }

    /**
     * @inheritDoc
     * Forward trait method
     */
    public function hasUser(): bool
    {
        return $this->_t_hasUser();
    }

    /**
     * @inheritDoc
     * Forward trait method
     */
    public function getUser(): ?UserInterface
    {
        return $this->_t_getUser();
    }

    /**
     * @inheritDoc
     * Forward trait method
     */
    public function requireUser(): UserInterface
    {
        return $this->_t_requireUser();
    }


    /**
     * Performs a logout for a given identity or the current logged user's identity
     * IMPORTANT: Always use this method for logout in your application to ensure further version compatibility with Skyline CMS.
     *
     * @param IdentityInterface|NULL $identity
     * @return bool
     */
    public function logoutIdentity(IdentityInterface $identity = NULL): bool {
        if(!$identity)
            $identity = $this->getIdentity();

        /** @var IdentityInstaller $installer */
        $installer = ServiceManager::generalServiceManager()->get( IdentityInstaller::SERVICE_NAME );


        /** @var Response $response */
        $response = ServiceManager::generalServiceManager()->get("response");

        $done = true;
        foreach($installer->getReachableProviders() as $provider) {
            if(!$provider->uninstallIdentity($identity, $response))
                $done = false;
        }
        return $done;
    }

    /**
     * Checks, if the logged user is member of a given group
     *
     * @param int|string $group  A group name or group id
     * @return bool
     */
    public function isMember($group): bool {
        if($user = $this->getUser()) {
            $g = ServiceManager::generalServiceManager()->get( UserGroupTool::SERVICE_NAME )->getGroups();
            return isset($g[$group]) || in_array($group, $g);
        }
        return false;
    }

    /**
     * Returns all roles the user has
     * @return array|null       The roles as strings
     */
    public function getUserRoles(): ?array {
        if($user = $this->getUser()) {
            if(NULL === $this->cachedUserRoles)
                $this->cachedUserRoles = array_map(function($r) {if($r instanceof RoleInterface){return$r->getRole();}else{return(string)$r;}}, $user->getRoles());
            return $this->cachedUserRoles;
        }
        return NULL;
    }

    /**
     * Checks, if the current logged user has one specific role
     *
     * @param string|RoleInterface $role
     * @return bool
     */
    public function hasRole($role): bool {
        if($user = $this->getUser()) {
            if($role instanceof RoleInterface)
                $role = $role->getRole();
            return in_array($role, $this->getUserRoles());
        }
        return false;
    }

    /**
     * Checks, if the current logged user has the required roles.
     * You may pass an array with role names, so the user must have all given roles or
     * a string in the following format
     *
     * The symbol && combines two roles as AND, so the user must have both roles
     * The symbol || combines two roles as OR, so the user must have at least one of the two roles
     *
     *
     *  "ROLE.1 && ROLE.2"              => true, if the user has ROLE.1 and ROLE.2
     *  "ROLE.1 || ROLE.2"              => true, if the user has ROLE.1 or ROLE.2
     *  "(ROLE.1 || ROLE.2) && ROLE.3"  => true, if the user has ROLE.1 or ROLE.2, and if so then has ROLE.3
     *
     * @param string|iterable $roles
     * @return bool
     */
    public function hasRoles($roles): bool {
        if($user = $this->getUser()) {
            if(is_iterable($roles)) {
                foreach($roles as $role) {
                    if(!$this->hasRole($role))
                        return false;
                }
                return true;
            } else {
                $roles = preg_replace_callback("/([a-z_\.0-9]+)/i", function($ms) {
                    $role = $ms[1];
                    if($this->hasRole($role))
                        return 1;
                    return 0;
                }, $roles);
                return eval("return $roles;") ? true : false;
            }
        }
        return false;
    }


}