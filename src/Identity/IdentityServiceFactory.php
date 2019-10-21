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


use Skyline\Security\Exception\SecurityException;
use Skyline\Security\Identity\IdentityService;
use Skyline\Security\Identity\Provider\ChainIdentityProvider;
use Skyline\Security\Identity\Provider\IdentityProviderFactoryInterface;
use Skyline\Security\Identity\Provider\IdentityProviderInterface;
use TASoft\Service\Container\AbstractContainer;
use TASoft\Service\Container\ConfiguredServiceContainer;
use TASoft\Service\ServiceManager;

class IdentityServiceFactory extends AbstractContainer
{
    const IDENTITY_SERVICE = 'identityService';

    const CONFIG_PROVIDERS = 'providers';

    // In list of providers, use this names with the service initialization structure:
    //  [
    //      IdentityServiceFactory::PROVIDER_NAME_REMEMBER_ME => [
    //          AbstractFileConfiguration::SERVICE_CLASS => AnonymousIdentityProvider::class,
    //          AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
    //              /* privoder-key */ 'my-application',
    //              /* app-secret */ 'my-secret'
    //          ]
    //      ]
    //  ]
    //  See class constructor for arguments.
    //  Arguments may contain services and parameters.

    const PROVIDER_NAME_ANONYMOUS = 'p_anony';
    const PROVIDER_NAME_REMEMBER_ME = 'remember-me';
    const PROVIDER_NAME_SESSION = 'session';

    const PROVIDER_NAME_HTTP_BASIC = 'http-basic';
    const PROVIDER_NAME_HTTP_DIGEST = 'http-digest';

    const PROVIDER_NAME_HTTP_POST = 'http-post';

    // This constant declares the enabled providers and their order.
    // Please note, that the CONFIG_PROVIDERS key is used to declare, how to initialize the given providers.
    // The CONFIG_ENABLED defines their order and which of them are in use.
    // List here only the names from above.
    const CONFIG_ENABLED = 'enabled-providers';


    private $configuration;

    /**
     * @return mixed
     */
    public function getConfiguration()
    {
        return $this->configuration;
    }

    /**
     * @param mixed $configuration
     */
    public function setConfiguration($configuration): void
    {
        $this->configuration = $configuration;
    }

    protected function loadInstance()
    {
        if($enabled = $this->getConfiguration()[ static::CONFIG_ENABLED ] ?? NULL) {
            $providerChain = new ChainIdentityProvider();

            foreach($enabled as $providerName) {
                $providerInfo = $this->getConfiguration()[ static::CONFIG_PROVIDERS ] [ $providerName ] ?? NULL;
                if(!$providerInfo)
                    throw new SecurityException("No provider declared for $providerName", 403);

                $sm = ServiceManager::generalServiceManager();
                $container = new ConfiguredServiceContainer($providerName, $providerInfo, $sm);
                $provider = $container->getInstance();
                if($provider instanceof IdentityProviderInterface || $provider instanceof IdentityProviderFactoryInterface) {
                    $providerChain->addProvider($provider);
                } else
                    throw new SecurityException("Initialization of provider $providerName failed. Not a provider returned from service container", 403);
            }

            return new IdentityService($providerChain);
        } else {
            throw new SecurityException("No identity providers specified for this application", 403);
        }
    }
}