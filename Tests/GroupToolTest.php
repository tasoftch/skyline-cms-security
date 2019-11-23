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

/**
 * GroupToolTest.php
 * skyline-cms-security
 *
 * Created on 2019-11-23 14:55 by thomas
 */

use PHPUnit\Framework\TestCase;
use Skyline\CMS\Security\Tool\UserGroupTool;
use Skyline\CMS\Security\UserSystem\Group;
use Skyline\PDO\MySQL;

class GroupToolTest extends TestCase
{
    private function createTool(): UserGroupTool {
        $PDO = new MySQL('localhost', 'skyline_dev', 'root', 'tasoftapps', '/tmp/mysql.sock');
        $tool = new UserGroupTool($PDO);
        $tool->disableEvents();
        return $tool;
    }

    public function testGroups() {
        $tool = $this->createTool();

        $admin = $tool->getGroup("Administrator");
        $this->assertInstanceOf(Group::class, $admin);
        $this->assertEquals(1, $admin->getId());
        $this->assertEquals(0, $admin->getOptions());
        $this->assertTrue($admin->isInternal());
    }


}
