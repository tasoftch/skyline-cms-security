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

use Skyline\CMS\Security\Authentication\AuthenticationServiceFactory;
use Skyline\CMS\Security\Authorization\AuthorizationServiceFactory;
use Skyline\CMS\Security\Challenge\ChallengeManager;
use Skyline\CMS\Security\Challenge\TemplateChallenge;
use Skyline\CMS\Security\Identity\IdentityInstaller;
use Skyline\CMS\Security\Identity\IdentityInstallerServiceFactory;
use Skyline\CMS\Security\Identity\IdentityServiceFactory;
use Skyline\CMS\Security\Tool\PasswordResetTool;
use Skyline\CMS\Security\Tool\UserTool;
use Skyline\CMS\Security\UserSystem\PermissionChangedValidator;
use Skyline\CMS\Security\UserSystem\UserProvider;
use Skyline\Kernel\Config\MainKernelConfig;
use Skyline\Security\Authentication\AuthenticationService;
use Skyline\Security\Authentication\Challenge\HTTP\BasicChallenge;
use Skyline\Security\Authentication\Challenge\HTTP\DigestChallenge;
use Skyline\Security\Authentication\Validator\Factory\AutoLogoutValidatorFactory;
use Skyline\Security\Authentication\Validator\Factory\BruteForceByClientIPValidatorFactory;
use Skyline\Security\Authentication\Validator\Factory\BruteForceByServerURIValidatorFactory;
use Skyline\Security\Authorization\AuthorizationService;
use Skyline\Security\Authorization\Voter\RoleChainVoter;
use Skyline\Security\Authorization\Voter\RoleRootVoter;
use Skyline\Security\Encoder\BCryptPasswordEncoder;
use Skyline\Security\Encoder\MessageDigestPasswordEncoder;
use Skyline\Security\Encoder\PlaintextPasswordEncoder;
use Skyline\Security\Encoder\PlaintextSaltPasswordEncoder;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\IdentityService;
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
                            'challenge' => '$' . ChallengeManager::HTTP_BASIC_CHALLENGE_SERVICE
                        ]
                    ],

                    // HTTP Digest Authentication
                    IdentityServiceFactory::PROVIDER_NAME_HTTP_DIGEST => [
                        AbstractFileConfiguration::SERVICE_CLASS => DigestIdentityProvider::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'challenge' => '$' . ChallengeManager::HTTP_DIGEST_CHALLENGE_SERVICE
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
            ],
            AbstractFileConfiguration::CONFIG_SERVICE_TYPE_KEY => IdentityService::class
        ],
        ChallengeManager::HTTP_DIGEST_CHALLENGE_SERVICE => [
            AbstractFileConfiguration::SERVICE_CLASS => DigestChallenge::class,
            AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                'realm' => '%security.http.digest.realm%',
                'nonce' => '%security.http.digest.nonce%',
                'opaque' => '%security.http.digest.opaque%'
            ]
        ],
        ChallengeManager::HTTP_BASIC_CHALLENGE_SERVICE => [
            AbstractFileConfiguration::SERVICE_CLASS => BasicChallenge::class,
            AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                'realm' => '%security.http.basic.realm%'
            ]
        ],
        ChallengeManager::HTTP_POST_CHALLENGE_SERVICE => [
            AbstractFileConfiguration::SERVICE_CLASS => TemplateChallenge::class,
            AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                'mainTemplateName' => '%security.challenge.main-template%',
                "childTemplateNames" => '%security.challenge.child-templates%'
            ]
        ],
        ChallengeManager::SERVICE_NAME => [
            AbstractFileConfiguration::SERVICE_CLASS => ChallengeManager::class,
            AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                'challengeMap' => [
                    BasicIdentityProvider::class => ChallengeManager::HTTP_BASIC_CHALLENGE_SERVICE,
                    DigestIdentityProvider::class => ChallengeManager::HTTP_DIGEST_CHALLENGE_SERVICE,
                    POSTFieldsIdentityProvider::class => ChallengeManager::HTTP_POST_CHALLENGE_SERVICE
                ],
                'reliabilities' => [
                    IdentityInterface::RELIABILITY_HTTP => ChallengeManager::HTTP_DIGEST_CHALLENGE_SERVICE,
                    IdentityInterface::RELIABILITY_HTTP-1 => ChallengeManager::HTTP_BASIC_CHALLENGE_SERVICE,
                    IdentityInterface::RELIABILITY_HTML_FORM => ChallengeManager::HTTP_POST_CHALLENGE_SERVICE
                ]
            ]
        ],

        AuthenticationServiceFactory::AUTHENTICATION_SERVICE => [
            AbstractFileConfiguration::SERVICE_CONTAINER => AuthenticationServiceFactory::class,
            AbstractFileConfiguration::SERVICE_INIT_CONFIGURATION => [
                AuthenticationServiceFactory::PASSWORD_ENCODERS => [
                    MessageDigestPasswordEncoder::class => [
                        AbstractFileConfiguration::SERVICE_CLASS => MessageDigestPasswordEncoder::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'algorythm' => 'sha512',
                            'base64' => true,
                            'iterations' => 5000
                        ]
                    ],
                    BCryptPasswordEncoder::class => [
                        AbstractFileConfiguration::SERVICE_CLASS => BCryptPasswordEncoder::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'cost' => 30,
                        ]
                    ],
                    PlaintextSaltPasswordEncoder::class => [
                        AbstractFileConfiguration::SERVICE_CLASS => PlaintextSaltPasswordEncoder::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'caseInsensitive' => '%security.password.ignoreCase%',
                        ]
                    ],
                    PlaintextPasswordEncoder::class => [
                        AbstractFileConfiguration::SERVICE_CLASS => PlaintextPasswordEncoder::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'caseInsensitive' => '%security.password.ignoreCase%',
                        ]
                    ]
                ],
                AuthenticationServiceFactory::ANONYMOUT_USER_ID => '%security.user.anonymous%',
                AuthenticationServiceFactory::ALLOWS_REMEMBER_ME => '%security.allows-remember-me%',
                AuthenticationServiceFactory::USER_PROVIDERS => [
                    [
                        AbstractFileConfiguration::SERVICE_CLASS => UserProvider::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'PDO' => '$PDO'
                        ]
                    ]
                ],
                AuthenticationServiceFactory::VALIDATORS => [
                    AuthenticationServiceFactory::VALIDATOR_CLIENT_BRUTE_FORCE => [
                        AbstractFileConfiguration::SERVICE_CLASS => BruteForceByClientIPValidatorFactory::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'file' => '%security.persistence%',
                            'attempts' => '%security.brute-force.client.maximal.attempts%',
                            'blocking' => '%security.brute-force.client.blocking.interval%'
                        ]
                    ],
                    AuthenticationServiceFactory::VALIDATOR_SERVER_BRUTE_FORCE => [
                        AbstractFileConfiguration::SERVICE_CLASS => BruteForceByServerURIValidatorFactory::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'file' => '%security.persistence%',
                            'attempts' => '%security.brute-force.server.maximal.attempts%',
                            'blocking' => '%security.brute-force.server.blocking.interval%'
                        ]
                    ],
                    AuthenticationServiceFactory::VALIDATOR_AUTO_LOGOUT => [
                        AbstractFileConfiguration::SERVICE_CLASS => AutoLogoutValidatorFactory::class,
                        AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                            'file' => '%security.persistence%',
                            'interval' => '%security.autologout.maximal-inactive%'
                        ]
                    ],
                    AuthenticationServiceFactory::VALIDATOR_PERMISSION_CHANGED => [
                        AbstractFileConfiguration::SERVICE_CLASS => PermissionChangedValidator::class
                    ]
                ],
                AuthenticationServiceFactory::ENABLED_VALIDATORS => '%security.validators.enabled%',
                AuthenticationServiceFactory::ENABLED_PASSWORD_ENCODERS => '%security.password-encoders.enabled%',
                AuthenticationServiceFactory::VALIDATOR_INSTALLER_NAME => IdentityInstaller::SERVICE_NAME
            ],
            AbstractFileConfiguration::CONFIG_SERVICE_TYPE_KEY => AuthenticationService::class
        ],
        IdentityInstaller::SERVICE_NAME => [
            AbstractFileConfiguration::SERVICE_CONTAINER => IdentityInstallerServiceFactory::class,
            AbstractFileConfiguration::SERVICE_INIT_CONFIGURATION => [
                IdentityInstallerServiceFactory::IDENTITY_SERVICE_NAME => IdentityServiceFactory::IDENTITY_SERVICE,
                IdentityInstallerServiceFactory::INSTALLABLES => [
                    // Here are available mappings
                    // This means, if the key identity provider successfully creates an identity that was authenticated,
                    // then all providers in values get an install identity command.
                    // Please note that classes are compared by names (not instanceof)
                    POSTFieldsIdentityProvider::class => [
                        POSTFieldsIdentityProvider::class,
                        SessionIdentityProvider::class,
                        RememberMeIdentityProvider::class
                    ],
                    BasicIdentityProvider::class => [
                        BasicIdentityProvider::class
                    ],
                    DigestIdentityProvider::class => [
                        DigestIdentityProvider::class
                    ],
                    AnonymousIdentityProvider::class => [
                        AnonymousIdentityProvider::class
                    ]
                ]
            ],
            AbstractFileConfiguration::CONFIG_SERVICE_TYPE_KEY => IdentityInstaller::class
        ],
        AuthorizationServiceFactory::SERVICE_NAME => [
            AbstractFileConfiguration::SERVICE_CONTAINER => AuthorizationServiceFactory::class,
            AbstractFileConfiguration::SERVICE_INIT_CONFIGURATION => [
                AuthorizationServiceFactory::VOTERS => [
                    RoleRootVoter::class,
                    RoleChainVoter::class
                ],
                AuthorizationServiceFactory::STRATEGY => '%security.authorization.strategy%',
                AuthorizationServiceFactory::ALLOW_IF_ABSTAIN => '%security.authorization.allowIfAllAbstain%',
                AuthorizationServiceFactory::ALLOW_IF_EQUAL => '%security.authorization.allowIfEqualGrantedAndDenied%',
            ],
            AbstractFileConfiguration::CONFIG_SERVICE_TYPE_KEY => AuthorizationService::class
        ],

        UserTool::SERVICE_NAME => [
            AbstractFileConfiguration::SERVICE_CLASS => UserTool::class,
            AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                'pdo' => '$PDO'
            ]
        ],
        PasswordResetTool::SERVICE_NAME => [
            AbstractFileConfiguration::SERVICE_CLASS => PasswordResetTool::class,
            AbstractFileConfiguration::SERVICE_INIT_ARGUMENTS => [
                'pdo' => '$PDO'
            ]
        ]
    ]
];
