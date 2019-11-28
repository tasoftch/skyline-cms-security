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

namespace Skyline\CMS\Security;

use Skyline\CMS\Security\Challenge\ChallengeManager;
use Skyline\CMS\Security\Exception\FailedChallengeException;
use Skyline\CMS\Security\Exception\LessReliabilityException;
use Skyline\Render\Model\ExtractableArrayModel;
use Skyline\Security\Authentication\AuthenticationServiceInterface;
use Skyline\Security\Authentication\Challenge\ChallengeInterface;
use Skyline\Security\Authorization\AuthorizationServiceInterface;
use Skyline\Security\Exception\Auth\NoIdentityException;
use Skyline\Security\Exception\AuthorizationException;
use Skyline\Security\Exception\SecurityException;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\IdentityService;
use Skyline\Security\Identity\IdentityServiceInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use TASoft\Service\ServiceManager;
use Throwable;

/**
 * The security trait should be used to extend action controllers by importing several security features.
 * @package Skyline\CMS\Security
 */
trait SecurityTrait
{
    /** @var IdentityInterface */
    private static $identity;
    /** @var UserInterface */
    private static $user;

    /**
     * Your application should perform code that protects action with this method.
     * This method performs the code and will catch all security exceptions that can be resolved by challenging the client for credentials.
     * If you don't use this method, you need to handle the security exceptions yourself.
     *
     * @param callable $code
     * @param ChallengeInterface|string|null $preferredChallenge    A preferred challenge. Can also be a valid challenge service name
     */
    protected function performCodeUnderChallenge(callable $code, $preferredChallenge = NULL) {
        try {
            call_user_func($code);
        } catch (SecurityException $exception) {
            if($exception->getCode() == 401)
                $this->challengeClient($exception, $preferredChallenge);
            else
                $this->denyRequest($this->getRequest(), $exception);
        }
    }

    /**
     * Called if the requesting client is not yet permitted to perform required action.
     * But the client has a chance to identity himself and then try again.
     *
     * @param SecurityException $exception
     * @param ChallengeInterface|string|null $preferredChallenge
     */
    protected function challengeClient(SecurityException $exception, $preferredChallenge = NULL) {
        $challenge = $this->getChallengeManager()->getChallenge( $preferredChallenge );
        if(!$challenge) {
            $reliability = 0;
            if(method_exists($exception, 'getReliability'))
                $reliability = $exception->getReliability();

            if($reliability)
                $challenge = $this->getChallengeManager()->getChallengeForReliability( $reliability );
            elseif(method_exists($exception, "getProvider"))
                $challenge = $this->getChallengeManager()->getChallengeForProvider( $exception->getProvider() );
            else
                $challenge = $this->getChallengeManager()->getBestReliabilityChallenge();

            if(method_exists($challenge, 'setModel')) {
                $challenge->setModel( new ExtractableArrayModel( ["exception" => $exception] ) );
            }

            if(!$challenge || !$challenge->challengeClient( $this->getResponse() )) {
                $e = new FailedChallengeException("Could not challenge client", 403);
                if($challenge) $e->setChallenge($challenge);
                throw $e;
            }
        }
    }

    /**
     * Called if a request is not allowed or anything else went wrong during authentication
     *
     * @param Request $request
     * @param SecurityException $exception
     */
    protected function denyRequest(Request $request, SecurityException $exception) {
        throw $exception;
    }

    /**
     * Tries to obtain an identity with minimal reliability.
     *
     * @param int $minimalReliability
     * @param IdentityInterface $minimalFound
     * @return IdentityInterface|null
     */
    protected function getIdentity($minimalReliability = 0, IdentityInterface &$minimalFound = NULL): ?IdentityInterface {
        if(NULL === self::$identity || (self::$identity instanceof IdentityInterface && self::$identity->getReliability() < $minimalReliability)) {
            if($minimalReliability) {
                $is = $this->getIdentityService();
                if($is instanceof IdentityService) {
                    self::$identity = $is->getIdentityWithReliabilityMin($this->getRequest(), $minimalReliability, $minimalFound);
                } else {
                    self::$identity = $this->getIdentityService()->getIdentityWithReliability($this->getRequest(), $minimalReliability);
                }
            }
            else
                self::$identity = $this->getIdentityService()->getIdentity($this->getRequest());

            if(!self::$identity)
                self::$identity = false;
            self::$user = NULL;
        }
        return self::$identity ?: NULL;
    }

    /**
     * This method requires the identity. If it was not set yet, try to obtain and on failure denies the request with an authentication challenge.
     *
     * @param int $minimalReliability
     * @return IdentityInterface
     * @throws LessReliabilityException  Thrown if no identity with a minimal reliability is available
     */
    protected function requireIdentity($minimalReliability = 0): IdentityInterface {
        $increase = self::$identity ? true : false;

        if(!$this->getIdentity($minimalReliability, $minimal)) {
            if($increase || $minimal) {
                $e = new LessReliabilityException("No identity available with required reliability", 401);
                $e->setReliability($minimalReliability);
            }
            else
                $e = new NoIdentityException("No identity found on given request", 401);

            throw $e;
        }
        return self::$identity;
    }

    /**
     * Checks if an identity with minimal reliability is available.
     *
     * @param int $minimalReliability
     * @return bool
     */
    protected function hasIdentity($minimalReliability = 0): bool {
        if($identity = $this->getIdentity($minimalReliability)) {
            return $identity->getReliability()>=$minimalReliability ? true : false;
        }
        return false;
    }

    /**
     * Pushes the identity to internal storage
     *
     * @param IdentityInterface $identity
     */
    protected function pushIdentity(?IdentityInterface $identity) {
        self::$identity = $identity;
    }

    /**
     * Pushes the user to internal storage
     *
     * @param UserInterface|null $user
     */
    protected function pushUser(?UserInterface $user) {
        self::$user = $user;
    }


    /**
     * Tries to get an authenticated user
     *
     * @return UserInterface|null
     */
    protected function getUser(): ?UserInterface {
        if(NULL === self::$user) {
            $identity = $this->getIdentity();
            try {
                self::$user = $this->getAuthenticationService()->authenticateIdentity($identity, $this->getRequest());
            } catch (SecurityException $exception) {
                self::$user = false;
            } catch (Throwable $exception) {
                trigger_error($exception->getMessage(), E_USER_WARNING);
            }
        }
        return self::$user ?: NULL;
    }

    /**
     * Checks if the identity was already authenticated
     *
     * @return bool
     */
    protected function hasUser(): bool {
        return self::$user ? true : false;
    }


    /**
     * This method requires a user now.
     *
     * @return UserInterface
     * @throws Throwable
     */
    protected function requireUser(): UserInterface {
        if($this->hasUser())
            return self::$user;
        return self::$user = $this->getAuthenticationService()->authenticateIdentity( $this->getIdentity(), $this->getRequest() );
    }

    /**
     * @param $toObject
     * @param $requiredRoles
     * @return bool
     */
    protected function grantAccess($toObject, $requiredRoles): bool {
        try {
            if($user = $this->getUser()) {
                return $this->getAuthorizationService()->grantAccess($user, $toObject, $requiredRoles);
            }
        } catch (Throwable $throwable) {
        }
        return false;
    }

    /**
     * Also checks if access is granted, but will throw an exception and stop further executation of the code
     *
     * @param $toObject
     * @param $requiredRoles
     * @throws Throwable
     */
    protected function requireAccess($toObject, $requiredRoles) {
        if(!$this->getAuthorizationService()->grantAccess($this->requireUser(), $toObject, $requiredRoles)) {
            $e = new AuthorizationException("Operation is not permitted", 403);
            $e->setUser(self::$user);
            throw $e;
        }
    }


    // Supporter methods
    protected function getIdentityService(): IdentityServiceInterface {
        /** @var IdentityServiceInterface $s */
        $s = ServiceManager::generalServiceManager()->get( 'identityService' );
        return $s;
    }

    protected function getAuthenticationService(): AuthenticationServiceInterface {
        /** @var AuthenticationServiceInterface $s */
        $s = ServiceManager::generalServiceManager()->get( 'authenticationService' );
        return $s;
    }

    protected function getAuthorizationService(): AuthorizationServiceInterface {
        /** @var AuthorizationServiceInterface $s */
        $s = ServiceManager::generalServiceManager()->get( 'authorizationService' );
        return $s;
    }

    protected function getChallengeManager(): ChallengeManager {
        /** @var ChallengeManager $s */
        $s = ServiceManager::generalServiceManager()->get( 'challengeManager' );
        return $s;
    }

    protected function getRequest(): Request {
        /** @var Request $s */
        $s = ServiceManager::generalServiceManager()->get( 'request' );
        return $s;
    }

    protected function getResponse(): Response {
        /** @var Response $s */
        $s = ServiceManager::generalServiceManager()->get( 'response' );
        return $s;
    }
}