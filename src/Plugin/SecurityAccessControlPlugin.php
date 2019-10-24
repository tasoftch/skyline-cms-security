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

namespace Skyline\CMS\Security\Plugin;


use Skyline\Application\Controller\CustomRenderInformationInterface;
use Skyline\Application\Event\PerformActionEvent;
use Skyline\CMS\Security\Exception\RequiredTokenException;
use Skyline\CMS\Security\SecurityTrait;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\Render\Context\DefaultRenderContext;
use Skyline\Render\Info\RenderInfo;
use TASoft\EventManager\EventManager;
use TASoft\Service\ServiceManager;

class SecurityAccessControlPlugin
{
    use SecurityTrait;

    private $accessControl;

    public function __construct($aclFile)
    {
        $this->accessControl = require $aclFile;
    }

    public function authorizeAction(string $eventName, PerformActionEvent $event, EventManager $eventManager, ...$arguments)
    {
        $description = $event->getActionDescription();
        $calledMethod = $description->getActionControllerClass() . "::" . $description->getMethodName();

        if($info = $this->accessControl[$calledMethod] ?? NULL) {
            $actionController = $event->getActionController();

            if($actionController instanceof CustomRenderInformationInterface)
                $renderInfo = $actionController->getRenderInformation();
            else
                $renderInfo = new RenderInfo();

            /** @var DefaultRenderContext $ctx */
            $ctx = ServiceManager::generalServiceManager()->get("renderContext");
            $ctx->setRenderInfo($renderInfo);
            $event->setRenderInformation($renderInfo);

            $this->performCodeUnderChallenge(function() use ($info) {
                if(isset($info["l"])) {
                    $this->requireIdentity($info["l"]);
                }

                if($users = $info["t"] ?? NULL) {
                    $token = $this->requireIdentity()->getToken();
                    $ok = false;
                    foreach ($users as $user) {
                        if(strcasecmp($user, $token) === 0) {
                            $ok = true;
                            break;
                        }
                    }

                    if(!$ok) {
                        $e = new RequiredTokenException("A specific token is required", 401);
                        $e->setToken($token);
                        throw $e;
                    }
                }

                $users = $info["u"] ?? NULL;
                $groups = $info["g"] ?? NULL;
                $roles = $info["r"] ?? NULL;

                if($users||$groups||$roles) {
                    $user = $this->requireUser();
                    if($user instanceof User) {

                    }
                }
            });
        }
    }
}