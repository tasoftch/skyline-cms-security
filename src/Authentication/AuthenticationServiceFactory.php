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

namespace Skyline\CMS\Security\Authentication;


use InvalidArgumentException;
use Skyline\CMS\Security\Identity\IdentityInstaller;
use Skyline\Security\Authentication\AuthenticationService;
use Skyline\Security\Encoder\PasswordEncoderChain;
use Skyline\Security\Exception\SecurityException;
use Skyline\Security\User\Provider\ChainUserProvider;
use TASoft\Collection\AbstractCollection;
use TASoft\Service\Container\AbstractContainer;
use TASoft\Service\Container\ConfiguredServiceContainer;
use TASoft\Service\Exception\BadConfigurationException;
use TASoft\Service\ServiceManager;

class AuthenticationServiceFactory extends AbstractContainer
{
	const AUTHENTICATION_SERVICE = 'authenticationService';

	const PASSWORD_ENCODERS = 'password-encoders';
	const ANONYMOUT_USER_ID = 'anonymousUID';
	const ALLOWS_REMEMBER_ME = 'allowsRememberMe';
	const USER_PROVIDERS = 'userProviders';
	const VALIDATORS = 'validators';

	const ENABLED_VALIDATORS = 'enabledValidators';
	const ENABLED_PASSWORD_ENCODERS = 'enabledPasswordEncoders';
	const ENABLED_USER_PROVIDERS = 'enabledUserProviders';

	const VALIDATOR_CLIENT_BRUTE_FORCE = 'client-bf';
	const VALIDATOR_SERVER_BRUTE_FORCE = 'server-bf';
	const VALIDATOR_PERMISSION_CHANGED = 'perm-ch';
	const VALIDATOR_AUTO_LOGOUT = 'auto-lgo';
	const VALIDATOR_UPDATE_LAST_LOGIN_DATE = 'upd-last-login';

	const VALIDATOR_INSTALLER_NAME = 'installerName';

	const USER_PROVIDER_DATABASE_NAME = 'updb';
	const USER_PROVIDER_INITIAL_NAME = 'iusp';

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
		$allProviders = $this->getConfiguration()[ static::USER_PROVIDERS ] ?? [];
		$enabledUserProviders = AbstractCollection::makeArray( $this->getConfiguration()[ static::ENABLED_USER_PROVIDERS ] ?? []);

		$userProviders = [];
		foreach($allProviders as $name => $provider) {
			if(in_array($name, $enabledUserProviders))
				$userProviders[] = $provider;
		}


		$userProviders = array_filter($userProviders, function($k) use ($enabledUserProviders) {
			return in_array($k, $enabledUserProviders);
		}, ARRAY_FILTER_USE_KEY);

		if(!$userProviders)
			throw new InvalidArgumentException("Authentication service requires at least one user provider", 403);

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



		if(count($userProviders) > 1) {
			$userProvider = new ChainUserProvider();
			foreach ($userProviders as $provider)
				$userProvider->addProvider( $makeInstance($provider) );
		} else {
			foreach($userProviders as $provider) {
				$userProvider = $makeInstance($provider);
				break;
			}
		}

		$passwordEncoders = $this->getConfiguration()[static::PASSWORD_ENCODERS] ?? NULL;
		$enabledPasswordEncoders = $this->getConfiguration()[ static::ENABLED_PASSWORD_ENCODERS ] ?? NULL;

		if(!$enabledPasswordEncoders)
			throw new InvalidArgumentException("Authentication service requires at least one enabled password encoder", 403);


		if(count($enabledPasswordEncoders) > 1) {
			$passwordEncoder = new PasswordEncoderChain();
			foreach($enabledPasswordEncoders as $encoderClass) {
				$encoder = $passwordEncoders[ $encoderClass ] ?? NULL;
				if(!$encoder)
					throw new SecurityException("No password encoder specified for $encoderClass");

				$cnt = new ConfiguredServiceContainer("", $encoder, $sm);
				$passwordEncoder->addEncoder( $cnt->getInstance() );
				unset($cnt);
			}
		} else {
			foreach($enabledPasswordEncoders as $encoderClass) {
				$encoder = $passwordEncoders[ $encoderClass ] ?? NULL;
				if(!$encoder)
					throw new SecurityException("No password encoder specified for $encoderClass");

				$cnt = new ConfiguredServiceContainer("", $encoder, $sm);
				$passwordEncoder = $cnt->getInstance();
				unset($cnt);
				break;
			}
		}

		$validators = [];

		if($validatorNames = $this->getConfiguration()[static::ENABLED_VALIDATORS] ?? NULL) {
			foreach($validatorNames as $name) {
				$info = $this->getConfiguration()[ static::VALIDATORS ] [$name] ?? NULL;
				if(!$info)
					throw new InvalidArgumentException("Can not instantiate validator $name. No definition specified", 403);
				$cnt = new ConfiguredServiceContainer($name, $info, $sm);
				$validators[] = $cnt->getInstance();
			}
		}

		if($installer = $this->getConfiguration()[static::VALIDATOR_INSTALLER_NAME] ?? NULL) {
			$installer = $sm->get($installer);
			if($installer instanceof IdentityInstaller) {
				$validators[] = $installer;
			}
		}

		return new AuthenticationService($userProvider, $passwordEncoder, $validators);
	}
}