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

use Skyline\CMS\Security\Identity\IdentityInstaller;
use Skyline\CMS\Security\SecurityTrait;
use Skyline\Security\Identity\IdentityInterface;
use Symfony\Component\HttpFoundation\Response;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

/**
 * The user tool allows your application several actions around users, groups and roles.
 * @package Skyline\CMS\Security
 */
class UserTool
{
    const SERVICE_NAME = 'userTool';
    use SecurityTrait;

    /** @var PDO */
    private $PDO;

    /**
     * SecurityTool constructor.
     * @param $PDO
     */
    public function __construct($PDO)
    {
        $this->PDO = $PDO;
    }

    /**
     * Performs a logout for a given identity or the current logged user's identity
     *
     * @param IdentityInterface|NULL $identity
     * @return bool
     */
    public function logoutIdentity(IdentityInterface $identity = NULL): bool {
        if(!$identity)
            $identity = $this->getIdentity();

        /** @var IdentityInstaller $installer */
        $installer = ServiceManager::generalServiceManager()->get( IdentityInstaller::SERVICE_NAME );


        /** @var Response $response */
        $response = ServiceManager::generalServiceManager()->get("response");

        $done = true;
        foreach($installer->getReachableProviders() as $provider) {
            if(!$provider->uninstallIdentity($identity, $response))
                $done = false;
        }
        return $done;
    }
}