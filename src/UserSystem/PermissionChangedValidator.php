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

namespace Skyline\CMS\Security\UserSystem;


use Skyline\CMS\Security\Exception\PermissionChangedValidatorException;
use Skyline\Security\Authentication\Validator\AuthenticationPostValidatorInterface;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\User\AdvancedUserInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

class PermissionChangedValidator implements AuthenticationPostValidatorInterface
{
    public function isEnabled(): bool
    {
        return true;
    }


    public function grantAfterAuthentication(IdentityInterface $identity, ?UserInterface $user, Request $request): bool
    {
        if($user instanceof AdvancedUserInterface) {
            $options = $user->getOptions();

            if($options & User::OPTION_INVALIDATE_SESSION) {
                if(
                    $identity->getReliability() == IdentityInterface::RELIABILITY_SESSION OR
                    $identity->getReliability() == IdentityInterface::RELIABILITY_REMEMBER_ME
                ) {
                    $e = new PermissionChangedValidatorException("Permission changed during session", 401);
                    $e->setIdentity($identity);
                    $e->setValidator($this);
                    throw $e;
                }

                /** @var PDO $PDO */
                $PDO = ServiceManager::generalServiceManager()->get("PDO");

                $o = User::OPTION_INVALIDATE_SESSION;

                $PDO->inject("UPDATE SKY_USER SET options = (options &~ $o) WHERE username = ?")->send([$user->getUsername()]);
            }
        }
        return true;
    }
}