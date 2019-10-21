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

use Skyline\CMS\Security\Identity\IdentityServiceFactory;
use Skyline\Kernel\Config\MainKernelConfig;
use Skyline\Security\Authentication\Challenge\HTTP\BasicChallenge;
use Skyline\Security\Authentication\Challenge\HTTP\DigestChallenge;
use Skyline\Security\Identity\Provider\AnonymousIdentityProvider;
use Skyline\Security\Identity\Provider\HTTP\BasicIdentityProvider;
use Skyline\Security\Identity\Provider\HTTP\DigestIdentityProvider;
use Skyline\Security\Identity\Provider\HTTP\POSTFieldsIdentityProvider;
use Skyline\Security\Identity\Provider\Session\RememberMeIdentityProvider;
use Skyline\Security\Identity\Provider\Session\SessionIdentityProvider;
use TASoft\Service\Config\AbstractFileConfiguration;

return [
    MainKernelConfig::CONFIG_SERVICES => [
        IdentityServiceFactory::IDENTITY_SERVICE => [
            AbstractFileConfiguration::SERVICE_CONTAINER => IdentityServiceFactory::class,
            AbstractFileConfiguration::SERVICE_INIT_CONFIGURATION => [
                IdentityServiceFactory::CONFIG_PROVIDERS => [
                    // The anonymous provider
                    IdentityServiceFactory::PROVIDER_NAME_ANONYMOUS => [
                        AbstractFileConfiguration::SERVICE_CLASS => AnonymousIdentityProvider::class
                    ],

                    // Remember Me
                    IdentityServiceFactory::PROVIDER_NAME_REMEMBER_ME => [
                        AbstractFileConfiguration::SERVICE_CLASS => RememberMeIdentityProvider::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'providerKey' => '%security.session.provider%',
                            'secret' => '%security.remember-me.secret%',
                            'options' => '%security.remember-me.options%'
                        ]
                    ],

                    // Session Provider
                    IdentityServiceFactory::PROVIDER_NAME_SESSION => [
                        AbstractFileConfiguration::SERVICE_CLASS => SessionIdentityProvider::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'providerKey' => '%security.session.provider%',
                            'secret' => '%security.session.secret%',
                            'options' => '%security.session.options%'
                        ]
                    ],

                    // HTTP Basic Authentication
                    IdentityServiceFactory::PROVIDER_NAME_HTTP_BASIC => [
                        AbstractFileConfiguration::SERVICE_CLASS => BasicIdentityProvider::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'challenge' => '$httpBasicChallenge'
                        ]
                    ],

                    // HTTP Digest Authentication
                    IdentityServiceFactory::PROVIDER_NAME_HTTP_DIGEST => [
                        AbstractFileConfiguration::SERVICE_CLASS => DigestIdentityProvider::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'challenge' => '$httpDigestChallenge'
                        ]
                    ],

                    // HTML form sent with POST method
                    IdentityServiceFactory::PROVIDER_NAME_HTTP_POST => [
                        AbstractFileConfiguration::SERVICE_CLASS => POSTFieldsIdentityProvider::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'tokenFieldName' => "%security.http.post.tokenName%",
                            "credentialFieldName" => '%security.http.post.credentialName%'
                        ]
                    ]
                ],
                IdentityServiceFactory::CONFIG_ENABLED => '%security.identity.order%'
            ]
        ],
        'httpDigestChallenge' => [
            AbstractFileConfiguration::SERVICE_CLASS => DigestChallenge::class,
            AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                'realm' => '%security.http.digest.realm%',
                'nonce' => '%security.http.digest.nonce%',
                'opaque' => '%security.http.digest.opaque%'
            ]
        ],
        'httpBasicChallenge' => [
            AbstractFileConfiguration::SERVICE_CLASS => BasicChallenge::class,
            AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                'realm' => '%security.http.basic.realm%'
            ]
        ]
    ]
];
