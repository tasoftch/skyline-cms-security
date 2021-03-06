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


use TASoft\Service\ServiceManager;

abstract class AbstractSecurityTool
{
    const CRYPTING_KEY = '';
    protected $disableEvents = false;

    /**
     * Call this method to disable all events that might be triggered by security tools
     */
    public function disableEvents() {
        $this->disableEvents = true;
    }

    /**
     * Call this method to enable all events that might be triggered by security tools
     */
    public function enableEvents() {
        $this->disableEvents = false;
    }

    /**
     * @param $data
     * @return string
     */
    protected function encodeData($data) {
        $key = hash( 'sha256', static::CRYPTING_KEY );
        $iv = substr( hash( 'sha256', ServiceManager::generalServiceManager()->getParameter("security.tools.secret")  ), 0, 16 );

        return base64_encode( openssl_encrypt( $data, "AES-256-CBC", $key, 0, $iv ) );
    }

    /**
     * @param $data
     * @return string
     */
    protected function decodeData($data) {
        $key = hash( 'sha256', static::CRYPTING_KEY );
        $iv = substr( hash( 'sha256', ServiceManager::generalServiceManager()->getParameter("security.tools.secret") ) , 0, 16 );

        return openssl_decrypt( base64_decode($data), "AES-256-CBC", $key, 0, $iv  );
    }
}