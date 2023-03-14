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

use DateTime;
use Skyline\CMS\Security\Exception\InvalidIdentityTokenException;
use Skyline\CMS\Security\Identity\IdentityInstaller;
use Skyline\CMS\Security\Identity\TemporaryIdentity;
use Skyline\CMS\Security\SecurityTrait;
use Skyline\CMS\Security\Tool\Event\UserEvent;
use Skyline\CMS\Security\UserSystem\Group;
use Skyline\CMS\Security\UserSystem\UserProvider;
use Skyline\Kernel\Service\SkylineServiceManager;
use Skyline\PDO\PDOResourceInterface;
use Skyline\Security\Exception\Auth\NoIdentityException;
use Skyline\Security\Exception\Auth\WrongPasswordException;
use Skyline\Security\Exception\SecurityException;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\IdentityService;
use Skyline\Security\Identity\SessionIdentity;
use Skyline\Security\Role\RoleInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Response;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

/**
 * The user tool allows your application several actions around users, groups and roles.
 * @package Skyline\CMS\Security
 */
class UserTool extends AbstractSecurityTool
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

	private $cachedUserRoles = [];
	private $userRoleCache = [];
	private $userGroupsCache = [];

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
	 * @return int
	 */
	public function getUserID(): int {
		if($user = $this->getUser()) {
			if($user instanceof PDOResourceInterface)
				return $user->getID();
			else
				return $this->PDO->selectFieldValue("SELECT id FROM SKY_USER WHERE username = ? LIMIT 1", 'id', [$user->getUsername()]) * 1;
		}
		return -1;
	}

	/**
	 * This method checks if anyhow a user can be fetched from Skyline given an id, username or email address
	 *
	 * @param string|int $user
	 * @return bool
	 */
	public function exists($user): bool {
		$c = $this->getPDO()->selectFieldValue("SELECT count(id) AS c FROM SKY_USER WHERE id = :user OR username = :user OR ((options & 8) = 8 AND email = :user)", 'c', ['user' => $user]);
		return $c > 0 ? true : false;
	}

	/**
	 * Checks, if a username exists.
	 *
	 * @param string $username
	 * @return bool
	 */
	public function existsUsername(string $username): bool {
		$c = $this->getPDO()->selectFieldValue("SELECT count(id) AS c FROM SKY_USER WHERE username = :user", 'c', ['user' => $username]);
		return $c > 0 ? true : false;
	}

	/**
	 * Checks, if an email address exists.
	 *
	 * @param string $email
	 * @return bool
	 */
	public function existsEmail(string $email): bool {
		$c = $this->getPDO()->selectFieldValue("SELECT count(id) AS c FROM SKY_USER WHERE email = :user", 'c', ['user' => $email]);
		return $c > 0 ? true : false;
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

			if(!$this->disableEvents) {
				$e = new UserEvent();
				$e->setUser($identity);
				SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_LOGOUT, $e, $identity, $installer);
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
		if($uid = $this->getUserID()) {
			// $g = ServiceManager::generalServiceManager()->get( UserGroupTool::SERVICE_NAME )->getGroups();
			if(NULL === ($this->userGroupsCache[$uid] ?? NULL)) {

				$this->userGroupsCache[$uid]= [];
				foreach($this->PDO->select("SELECT
id
FROM SKY_GROUP
JOIN SKY_USER_GROUP ON groupid = id
WHERE user = $uid") as $record) {
					$this->userGroupsCache[$uid][] = $record["id"]*1;
				}
			}
			/** @var UserGroupTool $gt */
			$gt = ServiceManager::generalServiceManager()->get( UserGroupTool::SERVICE_NAME );
			if($g = $gt->getGroup($group)) {
				return in_array($g->getId(), $this->userGroupsCache[$uid]) ? true : false;
			}
		}
		return false;
	}

	/**
	 * Gets a list of all groups the current user is member
	 *
	 * @return Group[]|null
	 */
	public function getGroups(): ?array {
		$gt = ServiceManager::generalServiceManager()->get(UserGroupTool::SERVICE_NAME);
		if($gt instanceof UserGroupTool) {
			if($user = $this->getUser()) {
				if(method_exists($user, 'getId')) {
					$uid = $user->getId();
					fetch:
					$groups = [];

					foreach($this->PDO->select("SELECT groupid FROM SKY_USER_GROUP WHERE user = $uid") as $record) {
						if($g = $gt->getGroup( $record['groupid'] ))
							$groups[$g->getId()] = $g;
					}
					return $groups;
				} else {
					$uid = $this->PDO->selectFieldValue("SELECT id FROM SKY_USER WHERE username = ?", 'id', [$user->getUsername()]) * 1;
					if($uid)
						goto fetch;
				}
			}
		}
		return NULL;
	}

	/**
	 * Returns all roles the user has
	 * @return array|null       The roles as strings
	 */
	public function getUserRoles(): ?array {
		if($user = $this->getUser()) {
			if(!isset($this->cachedUserRoles[$user->getUsername()]) || NULL === $this->cachedUserRoles[$user->getUsername()]) {
				$this->cachedUserRoles[$user->getUsername()] = array_map(function($r) {if($r instanceof RoleInterface){return$r->getRole();}else{return(string)$r;}}, $user->getRoles());
				$this->userRoleCache[$user->getUsername()] = [];
			}
			return $this->cachedUserRoles[$user->getUsername()];
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
			if(!isset($this->userRoleCache[$user->getUsername()][$role])) {
				$roles = $this->getUserRoles();

				$this->userRoleCache[$user->getUsername()][$role] = false;
				foreach($roles as $r) {
					if(stripos($role, $r) === 0) {
						$this->userRoleCache[$user->getUsername()][$role] = true;
						break;
					}
				}
			}

			return $this->userRoleCache[$user->getUsername()][$role] ? true : false;
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
				$roles = preg_replace_callback("/([a-z_.0-9]+)/i", function($ms) {
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
	 * For temporary increasing reliability you may ask a user to enter the password.
	 * This password may be confirmed using this method.
	 *
	 * @param string $credential
	 * @param bool $silent
	 * @return bool
	 */
	public function verifyCredentials(string $credential, bool $silent = false): bool {
		$as = $this->getAuthenticationService();
		if(method_exists($as, 'getPasswordEncoder')) {
			$encoder = $as->getPasswordEncoder();
			if(!$this->hasIdentity()) {
				if(!$silent)
					throw new NoIdentityException("No current identity registered", 403);
				return false;
			}
			$identity = $this->getIdentity();
			$user = $this->getUser();

			if(!$encoder->isPasswordValid( $user->getCredentials(), $credential, $identity->getOptions() )) {
				if(!$silent)
					throw new WrongPasswordException("Password is not correct", 401);
				return false;
			}
			return true;
		} elseif(!$silent)
			throw new SecurityException("Can not obtain password encoder", 403);
		return false;
	}

	/**
	 * This method creates a new account request.
	 * It is designed to verify an email address before creating an account.
	 * Pack all necessary information into the request (as attributes) and pass it to this method.
	 * It will create an URL safe string that can be transmitted by
	 *
	 * @param string $username
	 * @param string $email
	 * @param string $secure
	 * @param array $attributes
	 * @param int $ttl
	 * @return string
	 * @throws \Exception
	 */
	public function makeAccountRequest(string $username, string $email, string $secure, array $attributes = [], int $ttl = 60): string {
		$key = hash( 'sha256', 'skyline-user-tool-account-request-token' );
		$iv = substr( hash( 'sha256', $secure  ), 0, 16 );

		$date = new DateTime("now +{$ttl}seconds");

		return urlencode( base64_encode( openssl_encrypt( serialize([
			'acct',
			$username,
			$email,
			$attributes,
			$date->format("Y-m-d G:i:s")
		]), "AES-256-CBC", $key, 0, $iv ) ) );
	}

    /**
     * Decodes an account request
     *
     * @param string $request
     * @param string $secure
     * @param string|null $username
     * @param string|null $email
     * @param array|null $attributes
     * @return int
     * @throws \Exception
     */
    public function decodeAccountRequest(string $request, string $secure, &$username = NULL, &$email = NULL, &$attributes = NULL): int {
        $key = hash( 'sha256', 'skyline-user-tool-account-request-token' );
        $iv = substr( hash( 'sha256', $secure  ), 0, 16 );

        $data = openssl_decrypt( base64_decode( urldecode( $request )), "AES-256-CBC", $key, 0, $iv  );
        error_clear_last();
        @(
        list($hdr, $u, $e, $a, $date) = unserialize($data)
        );
        if($hdr == 'acct' && !error_get_last()) {
            $date = new DateTime($date);
            if($date->getTimestamp() >= (new DateTime("now"))->getTimestamp()) {
                $username = $u;
                $email = $e;
                $attributes = $a;
                return 1;
            } else {
                trigger_error("Invalid token. Time is up, not yet valid", E_USER_WARNING);
                return -1;
            }
        } else
            error_clear_last();

        trigger_error("Invalid token. Could not decode", E_USER_WARNING);
        return 0;
    }

    /**
     * Please use the identity tokens very careful!
     * They can be used like OAuth, so an identity's token and credentials are stored inside the token.
     * You may pass this token in API calls for example to increase reliability temporary.
     * This mechanism is designed to temporary increase the reliability for a single API call.
     *
     * PLEASE NOTE: YOU USE THIS MECHANISM ON YOUR OWN RISK !!
     *
     * @param IdentityInterface $identity The identity to take its token and credentials
     * @param string $secure A secure passphrase to encrypt the identity information
     * @param int $ttl Time to live in secondy, how long the token is valid
     * @return string
     * @throws \Exception
     * @see UserTool::decodeTemporaryIdentityToken()
     */
    public function makeTemporaryIdentityToken(IdentityInterface $identity, string $secure, int $ttl = 60): string {
        $key = hash( 'sha256', 'skyline-user-tool-temporary-identity-token-service' );
        $iv = substr( hash( 'sha256', $secure  ), 0, 16 );

        $date = new DateTime("now +{$ttl}seconds");

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
     * @param string $token The token
     * @param string $secure The passphrase to decode the token
     * @param bool $use If true, will use it as yielded identity
     * @return TemporaryIdentity
     * @throws \Exception
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
            $date = new DateTime($date);
            if($date->getTimestamp() >= (new DateTime("now"))->getTimestamp()) {
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

	/**
	 * This is an experimental function!
	 * It will mark the current logged user to adapt another users role set, next time on authentication.
	 *
	 * Once the user is marked, the UserProvider needs to adapt the roles.
	 *
	 * The SQL table SKY_USER must have a field named `adapt_roles_from` with integer type.
	 *
	 * @param UserInterface|int|string|null $user
	 * @return bool
	 * @see UserProvider
	 */
	public function adaptRolesFromUser($user = NULL): bool {
		if($this->hasUser()) {
			$usrName = $this->PDO->quote( $this->getUserName() );

			if($user === NULL) {
				$this->PDO->exec("UPDATE SKY_USER SET adapt_roles_from = NULL WHERE username = $usrName");
				return true;
			} else {
				if($user instanceof UserInterface)
					$user = $user->getUsername();

				$ID = $this->PDO->selectFieldValue("SELECT id FROM SKY_USER WHERE id = :token OR username = :token", 'id', ['token' => $user]);

				if($ID) {
					$this->PDO->exec("UPDATE SKY_USER SET adapt_roles_from $ID WHERE username = $usrName");
					return true;
				}
			}
		}
		return false;
	}
}