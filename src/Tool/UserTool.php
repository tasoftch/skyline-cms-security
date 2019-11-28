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

use Skyline\CMS\Security\Exception\InvalidIdentityTokenException;
use Skyline\CMS\Security\Identity\IdentityInstaller;
use Skyline\CMS\Security\Identity\TemporaryIdentity;
use Skyline\CMS\Security\SecurityTrait;
use Skyline\CMS\Security\Tool\Attribute\AbstractAttribute;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\PDO\PDOResourceInterface;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\IdentityService;
use Skyline\Security\Identity\SessionIdentity;
use Skyline\Security\Role\RoleInterface;
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
        hasIdentity as public;
        getIdentity as public;
        requireIdentity as public;

        hasUser as public;
        getUser as public;
        requireUser as public;

        getIdentityService as public;
        getAuthenticationService as public;
        getAuthorizationService as public;
        getChallengeManager as public;
    }

    /** @var PDO */
    private $PDO;

    private $cachedUserRoles;
    private $cachedUserAttributes;
    private $attributeName2IDMap = [];
    private $userRoleCache;
    private $userGroupsCache;

    /**
     * SecurityTool constructor.
     * @param $PDO
     */
    public function __construct($PDO)
    {
        $this->PDO = $PDO;
    }

    /**
     * @return PDO
     */
    public function getPDO(): PDO
    {
        return $this->PDO;
    }


    /**
     * Gets the user name
     *
     * @return string
     */
    public function getUserName() {
        if($u = $this->getUser())
            return $u->getUsername();
        return "";
    }

    /**
     * Tries to get a readable full user name
     *
     * @return string
     */
    public function getFullUserName() {
        if($u = $this->getUser()) {
            if(method_exists($u, 'getFullName'))
                return $u->getFullName();
            return $this->getUserName();
        }
        return "";
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

        if($identity) {
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
        return false;
    }

    /**
     * Checks, if a remember me identity exists.
     *
     * @return bool
     */
    public function hasRememberMeIdentity(): bool {
        /** @var IdentityService $is */
        $is = $this->getIdentityService();

        foreach($is->yieldIdentities($this->getRequest()) as $identity) {
            if($identity instanceof SessionIdentity && $identity->isRememberMe())
                return true;
        }
        return false;
    }

    /**
     * Checks, if the logged user is member of a given group
     *
     * @param int|string $group  A group name or group id
     * @return bool
     */
    public function isMember($group): bool {
        if($user = $this->getUser()) {
            // $g = ServiceManager::generalServiceManager()->get( UserGroupTool::SERVICE_NAME )->getGroups();
            if(NULL === $this->userGroupsCache) {
                $uid = $user->getId();

                $this->userGroupsCache= [];
                foreach($this->PDO->select("SELECT
id
FROM SKY_GROUP
JOIN SKY_USER_GROUP ON groupid = id
WHERE user = $uid") as $record) {
                    $this->userGroupsCache[] = $record["id"]*1;
                }
            }
            /** @var UserGroupTool $gt */
            $gt = ServiceManager::generalServiceManager()->get( UserGroupTool::SERVICE_NAME );
            if($g = $gt->getGroup($group)) {
                return in_array($g->getId(), $this->userGroupsCache) ? true : false;
            }
        }
        return false;
    }

    /**
     * Returns all roles the user has
     * @return array|null       The roles as strings
     */
    public function getUserRoles(): ?array {
        if($user = $this->getUser()) {
            if(NULL === $this->cachedUserRoles) {
                $this->cachedUserRoles = array_map(function($r) {if($r instanceof RoleInterface){return$r->getRole();}else{return(string)$r;}}, $user->getRoles());
                $this->userRoleCache = [];
            }
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
            if(!isset($this->userRoleCache[$role])) {
                $roles = $this->getUserRoles();

                $this->userRoleCache[$role] = false;
                foreach($roles as $r) {
                    if(stripos($role, $r) === 0) {
                        $this->userRoleCache[$role] = true;
                        break;
                    }
                }
            }

            return $this->userRoleCache[$role] ? true : false;
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

    /**
     * Gets user attributes
     *
     * @param User|NULL $user
     * @return array|null
     */
    public function getAttributes(User $user = NULL): ?array {
        if(!$user)
            $user = $this->getUser();

        if($user) {
            $uid = $user->getId();

            if(!isset($this->cachedUserAttributes[$uid])) {
                $this->cachedUserAttributes[$uid] = [];

                foreach($this->PDO->select("SELECT
id,
       options,
       value,
       valueType,
       name,
       description,
       icon
FROM SKY_USER_ATTRIBUTE_Q
JOIN SKY_USER_ATTRIBUTE on attribute = id
WHERE user = $uid AND enabled = 1
ORDER BY name") as $record) {
                    $attr = AbstractAttribute::create($record);
                    if($attr) {
                        $this->cachedUserAttributes[$uid][ $record["id"]*1 ] = $attr;
                        $this->attributeName2IDMap[ strtolower($record["name"]) ] = $record["id"]*1;
                    }

                    else
                        trigger_error("Can not create user attribute {$record["name"]}", E_USER_NOTICE);
                }
            }

            return $this->cachedUserAttributes[$uid];
        }
        return NULL;
    }

    /**
     * Gets the required attribute of logged user if available
     *
     * @param string|int $attribute  attribute name or id
     * @return AbstractAttribute|null
     */
    public function getAttribute($attribute): ?AbstractAttribute {
        $attrs = $this->getAttributes();
        if(!is_numeric($attribute))
            $attribute = $this->attributeName2IDMap[ strtolower( (string) $attribute) ] ?? -1;
        return $attrs[ $attribute ] ?? NULL;
    }

    /**
     * Creates an empty instance for a user attribute
     *
     * @param $attributeIDorName
     * @return AbstractAttribute|null
     */
    public function makeAttribute($attributeIDorName): ?AbstractAttribute {
        $attr = $this->PDO->selectOne("SELECT id,
       0 as options,
       NULL as value,
       valueType,
       name,
       description,
       icon FROM SKY_USER_ATTRIBUTE WHERE id = ? OR name = ?", [$attributeIDorName, $attributeIDorName]);
        return AbstractAttribute::create($attr);
    }

    public function updateAttribute(AbstractAttribute $attribute, $value = NULL, int $options = NULL, bool $replace = true): bool {
        if($user = $this->getUser()) {
            $aid = $attribute->getId();
            if($user instanceof PDOResourceInterface) {

            } else {

            }
        }
    }

    /**
     * Please use the identity tokens very careful!
     * They can be used like OAuth, so an identity's token and credentials are stored inside the token.
     * You may pass this token in API calls for example to increase reliability temporary.
     * This mechanism is designed to temporary increase the reliability for a single API call.
     *
     * PLEASE NOTE: YOU USE THIS MECHANISM ON YOUR OWN RISK !!
     *
     * @param IdentityInterface $identity  The identity to take its token and credentials
     * @param string $secure                A secure passphrase to encrypt the identity information
     * @param int $ttl                      Time to live in secondy, how long the token is valid
     * @return string
     * @see UserTool::decodeTemporaryIdentityToken()
     */
    public function makeTemporaryIdentityToken(IdentityInterface $identity, string $secure, int $ttl = 60): string {
        $key = hash( 'sha256', 'skyline-user-tool-temporary-identity-token-service' );
        $iv = substr( hash( 'sha256', $secure  ), 0, 16 );

        $date = new \DateTime("now +{$ttl}seconds");

        return base64_encode( openssl_encrypt( serialize([
            'idty',
            $identity->getReliability(),
            $identity->getToken(),
            $identity->getCredentials(),
            $identity->getOptions(),
            $date->format("Y-m-d G:i:s")
        ]), "AES-256-CBC", $key, 0, $iv ) );
    }

    /**
     * Decodes a token back to a temporary identity.
     *
     * @param string $token     The token
     * @param string $secure    The passphrase to decode the token
     * @param bool $use         If true, will use it as yielded identity
     * @return TemporaryIdentity
     * @see UserTool::makeTemporaryIdentityToken()
     */
    public function decodeTemporaryIdentityToken(string $token, string $secure, bool $use = false): TemporaryIdentity {
        $key = hash( 'sha256', 'skyline-user-tool-temporary-identity-token-service' );
        $iv = substr( hash( 'sha256', $secure  ), 0, 16 );

        $data = openssl_decrypt( base64_decode($token), "AES-256-CBC", $key, 0, $iv  );
        error_clear_last();
        @(
            list($hdr, $reliability, $token, $credentials, $options, $date) = unserialize($data)
        );
        if($hdr == 'idty' && !error_get_last()) {
            $date = new \DateTime($date);
            if($date->getTimestamp() >= (new \DateTime("now"))->getTimestamp()) {
                $idty = new TemporaryIdentity($token, $credentials, $reliability);
                $idty->setOptions( $options );

                if($use)
                    $this->pushIdentity( $idty );

                return $idty;
            } else {
                throw new InvalidIdentityTokenException("Invalid token. Time is up, not yet valid", 19031);
            }
        } else
            error_clear_last();

        throw new InvalidIdentityTokenException("Invalid token. Could not decode", 19029);
    }
}