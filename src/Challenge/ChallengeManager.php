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

namespace Skyline\CMS\Security\Challenge;


use Skyline\Security\Authentication\Challenge\ChallengeInterface;
use Skyline\Security\Identity\Provider\IdentityProviderInterface;
use TASoft\Service\ServiceManager;

class ChallengeManager
{
    const SERVICE_NAME = 'challengeManager';

    const HTTP_BASIC_CHALLENGE_SERVICE = 'httpBasicChallenge';
    const HTTP_DIGEST_CHALLENGE_SERVICE = 'httpDigestChallenge';
    const HTTP_POST_CHALLENGE_SERVICE = 'httpPostChallenge';

    /** @var array */
    private $challengeMap;
    /** @var array */
    private $reliabilities;

    /**
     * ChallengeManager constructor.
     * @param $challengeMap
     * @param $reliabilities
     */
    public function __construct($challengeMap, $reliabilities)
    {
        $this->challengeMap = $challengeMap;

        ksort($reliabilities);
        $last = 0;

        foreach($reliabilities as $rel => $item) {
            $this->reliabilities["$last:$rel"] = $item;
            $last = $rel+1;
        }
    }


    /**
     * Resolves a given challenge into a valid challenge object.
     *
     * @param $challenge
     * @return ChallengeInterface|null
     */
    public function getChallenge($challenge): ?ChallengeInterface {
        if(is_string( $challenge )) {
            /** @var ChallengeInterface $challenge */
            $challenge = ServiceManager::generalServiceManager()->get( $challenge );
        }
        if($challenge instanceof ChallengeInterface)
            return $challenge;
        return NULL;
    }

    /**
     * Finds a challenge to get a minimal required reliability
     *
     * @param $reliability
     * @return ChallengeInterface|null
     */
    public function getChallengeForReliability($reliability): ?ChallengeInterface {
        foreach($this->reliabilities as $rel => $challengeServiceName) {
            list($min, $max) = explode(":", $rel, 2);
            if($reliability >= $min && $reliability < $max) {
                /** @var ChallengeInterface $s */
                $s = ServiceManager::generalServiceManager()->get( $challengeServiceName );
                return $s;
            }
        }
        return NULL;
    }

    /**
     * Finds a challenge to obtain an identity from a specific identity provider
     *
     * @param IdentityProviderInterface $provider
     * @return ChallengeInterface|null
     */
    public function getChallengeForProvider(IdentityProviderInterface $provider): ?ChallengeInterface {
        foreach($this->challengeMap as $provClass => $challengeServiceName) {
            if($provider instanceof $provClass) {
                /** @var ChallengeInterface $s */
                $s = ServiceManager::generalServiceManager()->get( $challengeServiceName );
                return $s;
            }
        }
        return NULL;
    }

    /**
     * Gets the challenge to obtain the maximal available reliability for an identity.
     *
     * @return ChallengeInterface|null
     */
    public function getBestReliabilityChallenge(): ?ChallengeInterface {
        $challengeServiceName = end($this->reliabilities);
        /** @var ChallengeInterface $s */
        $s = ServiceManager::generalServiceManager()->get( $challengeServiceName );
        return $s;
    }
}