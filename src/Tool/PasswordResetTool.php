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
use Skyline\CMS\Security\Tool\Token\PasswordResetToken;
use Skyline\CMS\Security\Tool\Token\TokenInterface;
use Skyline\Security\Authentication\AuthenticationService;
use Skyline\Security\User\AdvancedUserInterface;
use Skyline\Security\User\Provider\MutableUserProviderInterface;
use Skyline\Security\User\Provider\UserProviderInterface;
use Skyline\Security\User\UserInterface;
use TASoft\Service\ServiceManager;

class PasswordResetTool extends AbstractSecurityTool
{
    const SERVICE_NAME = 'passwordResetTool';
    const CRYPTING_KEY = 'security.tools.password-reset';

    const ERROR_CODE_INVALID_TOKEN = 102;
    const ERROR_CODE_TIME_LIMIT_REACHED = 103;
    const ERROR_CODE_NO_USER_PROVIDER_FOUND = 110;
    const ERROR_CODE_NO_USER_FOUND = 404;
    const ERROR_CODE_NOT_DEACTIVATED = 521;

    const ERROR_CODE_IMMUTABLE_PROVIDER = PasswordResetToken::ERROR_CODE_IMMUTABLE_PROVIDER;
    const ERROR_CODE_NO_PASSWORD_ENCODER_AVAILABLE = 530;
    const ERROR_CODE_INVALID_ENCODED_PASSWORD = 531;

    use SecurityTrait;

    /**
     * This method prepares a user to perform a password reset request.
     *
     * @param $anyUserinfo
     * @param bool $deactivateUser
     * @return PasswordResetToken|null
     */
    public function makePasswordResetToken($anyUserinfo, bool $deactivateUser = false): ?PasswordResetToken {
        if(ServiceManager::generalServiceManager()->getParameter( 'security.allows-password-reset' )) {
            $service = $this->getAuthenticationService();
            if(method_exists($service, 'getUserProvider')) {
                /** @var UserProviderInterface $userProvider */
                $userProvider = $service->getUserProvider();
                if($user = $userProvider->loadUserWithToken( $anyUserinfo )) {
                    if(!($userProvider instanceof MutableUserProviderInterface))
                        return new PasswordResetToken(false, $user, "", PasswordResetToken::ERROR_CODE_IMMUTABLE_PROVIDER);

                    if($deactivateUser) {
                        if($user instanceof AdvancedUserInterface) {
                            if($user->getOptions() & AdvancedUserInterface::OPTION_DEACTIVATED) {
                                return new PasswordResetToken(false, $user, "", PasswordResetToken::ERROR_CODE_USER_ALREADY_DEACTIVATED);
                            } else {
                                if(!$userProvider->setOptions( $user->getOptions() | AdvancedUserInterface::OPTION_DEACTIVATED, $user ))
                                    return new PasswordResetToken(false, $user, "", PasswordResetToken::ERROR_CODE_USER_DEACTIVATION_FAILED);
                            }
                        }
                    }

                    $data = serialize([
                        time(),
                        $anyUserinfo,
                        $deactivateUser
                    ]);
                    $token = $this->encodeData($data);
                    return new PasswordResetToken(true, $user, $token, 0);
                } else {
                    return new PasswordResetToken(false, NULL, "", PasswordResetToken::ERROR_CODE_USER_NOT_FOUND);
                }
            }
        }
        return NULL;
    }

    /**
     * Validates a password reset token.
     * If this method returns true, then the token is valid and the user may enter a new password under this token
     *
     * @param string|TokenInterface $token
     * @param UserInterface|null $user          The user if available
     * @param int $errorCode                    An integral number indicating, what went wrong. See class constants ERROR_CODE_*
     * @param int $remainingTime                Remaining seconds until the token gets invalid
     * @return bool
     */
    public function validatePasswordResetToken($token, UserInterface &$user = NULL, &$errorCode = -1, int &$remainingTime = 0): bool {
        if($token instanceof TokenInterface)
            $token = $token->getToken();

        $data = $this->decodeData($token);

        error_clear_last();
        $data = @unserialize( $data );
        if(error_get_last() || !is_array($data) || count($data) != 3) {
            error_clear_last();
           $errorCode = static::ERROR_CODE_INVALID_TOKEN;
           return false;
        }

        list($time, $anyUserInfo, $deactivateUser) = $data;
        $diff = time() - $time;

        $maximalInterval = ServiceManager::generalServiceManager()->getParameter("security.tool.password-reset.maximal-time");

        $remainingTime = max(0, $maximalInterval - $diff);

        if($diff < $maximalInterval) {
            $service = $this->getAuthenticationService();
            if(method_exists($service, 'getUserProvider')) {
                /** @var UserProviderInterface $userProvider */
                $userProvider = $service->getUserProvider();
                if($user = $userProvider->loadUserWithToken($anyUserInfo)) {
                    if($deactivateUser) {
                        if($user instanceof AdvancedUserInterface) {
                            if($user->getOptions() & AdvancedUserInterface::OPTION_DEACTIVATED) {} else {
                                $errorCode = static::ERROR_CODE_NOT_DEACTIVATED;
                                return false;
                            }
                        }
                    }
                    $errorCode = 0;
                    return true;
                } else
                    $errorCode = static::ERROR_CODE_NO_USER_FOUND;
            } else
                $errorCode = static::ERROR_CODE_NO_USER_PROVIDER_FOUND;
        } else {
            $errorCode = static::ERROR_CODE_TIME_LIMIT_REACHED;
            return false;
        }

        return false;
    }

    /**
     * Use this method to specify a new password for the user with a specified token
     *
     * @param string|TokenInterface $token
     * @param string $newPlainPassword
     * @param int $errorCode
     * @return bool
     */
    public function updatePassword($token, string $newPlainPassword, &$errorCode = -1) {
        if($this->validatePasswordResetToken($token, $user, $errorCode)) {
            /** @var AuthenticationService $service */
            $service = $this->getAuthenticationService();
            if(method_exists($service, 'getPasswordEncoder')) {
                $password = $service->getPasswordEncoder()->encodePassword($newPlainPassword, $options);
                if($password) {
                    $userProvider = $service->getUserProvider();
                    if($userProvider instanceof MutableUserProviderInterface) {
                        return $userProvider->setCredentials($password, $user, $options) ? true : false;
                    } else
                        $errorCode = static::ERROR_CODE_IMMUTABLE_PROVIDER;
                } else
                    $errorCode = static::ERROR_CODE_INVALID_ENCODED_PASSWORD;
            } else
                $errorCode = static::ERROR_CODE_NO_PASSWORD_ENCODER_AVAILABLE;
        }
        return false;
    }
}