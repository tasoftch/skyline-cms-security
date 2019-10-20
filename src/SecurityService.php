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


use Skyline\Security\Authentication\AuthenticationServiceInterface;
use Skyline\Security\Authorization\AuthorizationServiceInterface;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\IdentityServiceInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;

class SecurityService implements AuthorizationServiceInterface, AuthenticationServiceInterface, IdentityServiceInterface
{
    /** @var IdentityServiceInterface */
    private $identityService;
    /** @var AuthenticationServiceInterface */
    private $authenticationService;
    /** @var AuthorizationServiceInterface */
    private $authorizationService;

    public function getIdentity(Request $request): ?IdentityInterface
    {
        // TODO: Implement getIdentity() method.
    }

    public function getIdentityWithReliability(Request $request, int $reliability): ?IdentityInterface
    {
        // TODO: Implement getIdentityWithReliability() method.
    }

    public function authenticateIdentity(?IdentityInterface $identity, Request $request, $specificPasswordEncoder = NULL): UserInterface
    {
        // TODO: Implement authenticateIdentity() method.
    }

    public function grantAccess(UserInterface $user, $object, array $attributes = []): bool
    {
        // TODO: Implement grantAccess() method.
    }
}