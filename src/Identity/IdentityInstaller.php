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

namespace Skyline\CMS\Security\Identity;

use Skyline\Security\Authentication\Validator\AuthenticationPostValidatorInterface;
use Skyline\Security\Exception\AuthenticationValidatorException;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\IdentityService;
use Skyline\Security\Identity\IdentityServiceInterface;
use Skyline\Security\Identity\Provider\ChainIdentityProvider;
use Skyline\Security\Identity\Provider\IdentityProviderChainInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;

class IdentityInstaller implements AuthenticationPostValidatorInterface
{
    /** @var array */
    private $mappings;
    /** @var IdentityServiceInterface */
    private $identityService;

    private $_reachableProviders;

    /**
     * IdentityInstaller constructor.
     * @param array $mappings
     * @param IdentityServiceInterface $identityService
     */
    public function __construct(array $mappings, IdentityServiceInterface $identityService)
    {
        $this->mappings = $mappings;
        $this->identityService = $identityService;
    }

    /**
     * @return array
     */
    public function getMappings(): array
    {
        return $this->mappings;
    }

    /**
     * @return IdentityServiceInterface
     */
    public function getIdentityService(): IdentityServiceInterface
    {
        return $this->identityService;
    }

    private function getReachableProviders(): array {
        if($this->_reachableProviders === NULL) {
            $this->_reachableProviders = [];

            $resolver = function($provider) use (&$resolver) {
                if($provider instanceof ChainIdentityProvider) {
                    foreach($provider->getProviders() as $prov)
                        yield from $resolver($prov);
                } else
                    yield $provider;
            };

            $is = $this->getIdentityService();
            if(method_exists($is, 'getProvider')) {
                foreach($resolver($is->getProvider()) as $provider) {
                    $this->_reachableProviders[ get_class($provider) ] = $provider;
                }
            }
        }
        return $this->_reachableProviders;
    }

    public function grantAfterAuthentication(IdentityInterface $identity, ?UserInterface $user, Request $request): bool
    {
        if($user) {
            // Only install, if authentication was successful

        } else {
            // Otherwise revoke installation

        }
        return true;
    }

    public function isEnabled(): bool
    {
        return true;
    }
}