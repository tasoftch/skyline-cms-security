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
use Skyline\CMS\Security\Exception\InvalidUserException;
use Skyline\CMS\Security\Exception\RequiredGroupMembershipException;
use Skyline\CMS\Security\Exception\RequiredRolesException;
use Skyline\CMS\Security\Exception\RequiredTokenException;
use Skyline\CMS\Security\Exception\RequiredUsernameException;
use Skyline\CMS\Security\SecurityTrait;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\CMS\Security\UserSystem\UserProvider;
use Skyline\Render\Context\DefaultRenderContext;
use Skyline\Render\Info\RenderInfo;
use Skyline\Security\Authentication\AbstractAuthenticationService;
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

            $this->performCodeUnderChallenge(function() use ($info, $event) {
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

                $users = $info["u"] ?? [];
                $groups = $info["g"] ?? [];
                $roles = $info["r"] ?? [];

                if($users||$groups||$roles||($info["a"] ?? false)) {
                    $user = $this->requireUser();
                    if($user instanceof User) {
                        if($users) {
                            $inList = false;
                            foreach($users as $u) {
                                if(strcasecmp($user->getUsername(), $u) === 0) {
                                    $inList=true;
                                    break;
                                }
                            }
                            if(!$inList) {
                                $e = new RequiredUsernameException("A specific username is required", 401);
                                $e->setUsername($user->getUsername());
                                $e->setIdentity($this->getIdentity());
                                throw $e;
                            }
                        }

                        if($groups) {
                            $as = $this->getAuthenticationService();
                            if($as instanceof AbstractAuthenticationService) {
                                $up = $as->getUserProvider();
                                if($up instanceof UserProvider) {
                                    $groups = array_map(function($A) { return strtolower($A); }, $groups);
                                    $inList = false;

                                    foreach($up->getMemberShip( $user->getUsername() ) as $gid => $name) {
                                        if(in_array($gid, $groups) || in_array(strtolower($name), $groups)) {
                                            $inList = true;
                                            break;
                                        }
                                    }

                                    if(!$inList) {
                                        $e = new RequiredGroupMembershipException("User is not member of specific group", 403);
                                        $e->setIdentity($this->getIdentity());
                                        $e->setUsername($user->getUsername());
                                        throw $e;
                                    }
                                } else {
                                    throw new RequiredGroupMembershipException("Can not verify group membership because your application is using a different user provider", 403);
                                }
                            }
                        }

                        if($roles) {
                            $as = $this->getAuthorizationService();
                            if(!$as->grantAccess($user, $event, $roles)) {
                                $e = new RequiredRolesException("Action not permitted", 403);
                                $e->setUser($user);
                                throw $e;
                            }
                        }
                    } else {
                        $e = new InvalidUserException("User %s is not supported by Skyline CMS", 403, NULL, $user->getUsername());
                        $e->setIdentity($this->getIdentity());
                        $e->setUsername($user->getUsername());
                        throw $e;
                    }
                }
            });
        }
    }
}