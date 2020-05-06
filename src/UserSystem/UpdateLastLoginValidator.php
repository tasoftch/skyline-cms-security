<?php

namespace Skyline\CMS\Security\UserSystem;


use Skyline\CMS\Security\Tool\Event\UserEvent;
use Skyline\Kernel\Service\SkylineServiceManager;
use Skyline\PDO\PDOResourceInterface;
use Skyline\Security\Authentication\Validator\AuthenticationPostValidatorInterface;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

class UpdateLastLoginValidator implements AuthenticationPostValidatorInterface
{
    private $fieldName;
    private $minimumReliability;
    private $withEvents;

    /**
     * UpdateLastLoginValidator constructor.
     * @param $fieldName
     */
    public function __construct($fieldName, $minimumReliability, bool $withEvents = true)
    {
        $this->fieldName = $fieldName;
        $this->minimumReliability = $minimumReliability;
        $this->withEvents = $withEvents;
    }

    public function enableEvents() {
    	$this->withEvents = true;
	}
	public function disableEvents() {
    	$this->withEvents = false;
	}

    public function grantAfterAuthentication(IdentityInterface $identity, ?UserInterface $user, Request $request): bool
    {
        if($user instanceof PDOResourceInterface && $identity->getReliability() >= $this->minimumReliability) {
            $uid = $user->getID();
            /** @var PDO $PDO */
            $PDO = ServiceManager::generalServiceManager()->get("PDO");
            $PDO->inject("UPDATE SKY_USER SET $this->fieldName = NOW() WHERE id = $uid")->send([]);
            
            if($this->withEvents) {
            	$e = new UserEvent();
            	$e->setUser($user);
            	SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_LOGIN, $e, $user, $identity, $request, $this);
			}
        }
        return true;
    }

    public function isEnabled(): bool
    {
        return true;
    }
}