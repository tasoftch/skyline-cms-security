<?php

namespace Skyline\CMS\Security\UserSystem;


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

    /**
     * UpdateLastLoginValidator constructor.
     * @param $fieldName
     */
    public function __construct($fieldName, $minimumReliability)
    {
        $this->fieldName = $fieldName;
        $this->minimumReliability = $minimumReliability;
    }


    public function grantAfterAuthentication(IdentityInterface $identity, ?UserInterface $user, Request $request): bool
    {
        if($user instanceof PDOResourceInterface && $identity->getReliability() >= $this->minimumReliability) {
            $uid = $user->getID();
            /** @var PDO $PDO */
            $PDO = ServiceManager::generalServiceManager()->get("PDO");

            $PDO->inject("UPDATE SKY_USER SET $this->fieldName = NOW() WHERE id = $uid")->send([]);
        }
        return true;
    }

    public function isEnabled(): bool
    {
        return true;
    }
}