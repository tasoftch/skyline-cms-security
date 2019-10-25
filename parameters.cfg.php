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
use Skyline\Security\Authorization\AbstractAuthorizationService;
use Skyline\Security\Authorization\AuthorizationServiceInterface;
use Skyline\Security\Identity\Provider\Session\RememberMeIdentityProvider;
use Skyline\Security\Identity\Provider\Session\SessionIdentityProvider;

return [
    // Security persistence is required to store security values like request counts, auto-logout and so on.
    // You may set a filename or a PDO object.
    'security.persistence' => '$(C)/security.persistent.sqlite',

    // Dynamically create a unique application provider string
    'security.session.provider' => md5(__FILE__),

    // Dynamically create unique secret
    'security.remember-me.secret' => md5(uniqid()),
    'security.remember-me.options' => [
        RememberMeIdentityProvider::OPTION_COOKIE_LIFETIME => 100 /* days */ * 24 * 3600,
        RememberMeIdentityProvider::OPTION_REMEMBER_ME => '%security.http.post.rememberMeName%',
        /**
         * Adjust remember-me cookie setup
         * @see RememberMeIdentityProvider::OPTION_* constants
         */

        // For example, make the remember-me service available for the whole domain:
        // RememberMeIdentityProvider::OPTION_COOKIE_DOMAIN => '.example.org'
    ],

    // Also create dynamically secrets different for sessions than remember me
    'security.session.secret' => md5(uniqid()),
    'security.session.options' => [
        /**
         * Adjust session cookie setup
         * @see SessionIdentityProvider::OPTION_* constants
         */
    ],

    'security.http.basic.realm' => 'Skyline Application',

    'security.http.digest.realm' => 'Skyline Application',
    // Set to null to grant pending authentication for an hour.
    // Putting a custom value, make sure that is can not be guessed.
    'security.http.digest.nonce' => "",
    'security.http.digest.opaque' => "",

    // HTTP Post, so html forms sent with post method are resolved as well using the following post field keys:
    'security.http.post.tokenName' => 'username',
    'security.http.post.credentialName' => 'password',
    'security.http.post.rememberMeName' => 'remember_me',

    'security.identity.order' => [
        // List here (at this position in your SkylineAppData/Config/parameters.config.php or parameters.config.dev.php file), which identity provider you want to use in your application and in which order.
        // In this example, they are ordered by their reliability.
        // So it will try to obtain an identity with the best available reliability by default

        // Please note: Enabling the anonymous provider you MUST specify an anonymous user as well!
        // Please note: You must declare at least one identity provider to enable security service!

        // IdentityServiceFactory::PROVIDER_NAME_HTTP_POST         // 500

        // IdentityServiceFactory::PROVIDER_NAME_SESSION,          // 200
        // IdentityServiceFactory::PROVIDER_NAME_REMEMBER_ME,      // 150

        // IdentityServiceFactory::PROVIDER_NAME_HTTP_DIGEST,      // 100
        // IdentityServiceFactory::PROVIDER_NAME_HTTP_BASIC,       // 100

        // IdentityServiceFactory::PROVIDER_NAME_ANONYMOUS,        // 10
    ],
    'security.challenge.main-template' => 'main',
    "security.challenge.child-templates" => [
        'Content' => '401'
    ],

    // Authentication
    "security.password.ignoreCase" => false,

    "security.user.anonymous" => 0,
    "security.allows-remember-me" => false,

    "security.brute-force.client.maximal.attempts" => 3,
    "security.brute-force.client.blocking.interval" => 900,
    "security.brute-force.server.maximal.attempts" => 3,
    "security.brute-force.server.blocking.interval" => 900,

    "security.autologout.maximal-inactive" => 900,
    "security.validators.enabled" => [
        // Define in your config file here which validators you want to use

        // AuthenticationServiceFactory::VALIDATOR_CLIENT_BRUTE_FORCE   // recommended
        // AuthenticationServiceFactory::VALIDATOR_AUTO_LOGOUT          // also recommended
        // AuthenticationServiceFactory::VALIDATOR_PERMISSION_CHANGED   // optional, if enabled, a logged user gets logged out if an administrator changes its permissions while session or remember-me session
    ],

    'security.http-post.allows-password-reset' => true,

    // Authorization
    'security.authorization.strategy' => AbstractAuthorizationService::STRATEGY_AFFIRMATIVE,
    'security.authorization.allowIfAllAbstain' => false,
    'security.authorization.allowIfEqualGrantedAndDenied' => true
];
