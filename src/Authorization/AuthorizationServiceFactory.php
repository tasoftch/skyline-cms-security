<?php
namespace Skyline\CMS\Security\Authorization;


use Skyline\Security\Authorization\AuthorizationService;
use Skyline\Security\Authorization\Voter\VoterInterface;
use TASoft\Service\Container\AbstractContainer;
use TASoft\Service\Container\ConfiguredServiceContainer;
use TASoft\Service\Exception\BadConfigurationException;
use TASoft\Service\ServiceManager;

class AuthorizationServiceFactory extends AbstractContainer
{
    const SERVICE_NAME = 'authorizationService';

    const VOTERS = 'voters';
    const STRATEGY = 'strategy';
    const ALLOW_IF_ABSTAIN = 'allowIfAbstain';
    const ALLOW_IF_EQUAL = 'allowIfEqualGrantedAndDenied';

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
        $voters = [];

        $sm = ServiceManager::generalServiceManager();
        $makeInstance = function($config) use ($sm) {
            try {
                $cnt = new ConfiguredServiceContainer("", $config, $sm);
            } catch (BadConfigurationException $exception) {
                return NULL;
            }
            $s = $cnt->getInstance();
            unset($cnt);
            return $s;
        };

        foreach($this->getConfiguration()[ static::VOTERS ] as $voter) {
            if(is_string($voter)) {
                $voter = new $voter();
            } elseif(is_array($voter))
                $voter = $makeInstance($voter);

            if($voter instanceof VoterInterface)
                $voters[] = $voter;
        }

        return new AuthorizationService($voters, $this->getConfiguration()[static::STRATEGY], $this->getConfiguration()[static::ALLOW_IF_ABSTAIN], $this->getConfiguration()[static::ALLOW_IF_EQUAL]);
    }
}