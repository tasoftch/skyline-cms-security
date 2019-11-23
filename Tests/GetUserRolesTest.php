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
 * GetUserRolesTest.php
 * skyline-cms-security
 *
 * Created on 2019-11-23 11:44 by thomas
 */

use PHPUnit\Framework\TestCase;
use Skyline\CMS\Security\Tool\UserRoleTool;
use Skyline\CMS\Security\UserSystem\Role;
use Skyline\PDO\MySQL;

class GetUserRolesTest extends TestCase
{
    private function createTool(): UserRoleTool {
        $PDO = new MySQL('localhost', 'skyline_dev', 'root', 'tasoftapps', '/tmp/mysql.sock');
        $tool = new UserRoleTool($PDO);
        $tool->disableEvents();
        return $tool;
    }

    public function testAddRole() {
        $tool = $this->createTool();

        $root = $tool->getRole("SKYLINE");
        $role = $tool->addRole("TEST", $root);

        $this->assertEquals('SKYLINE.TEST', $role->getRole());
        $this->assertEquals("", $role->getDescription());
        $this->assertEquals(0, $role->getOptions());

        $this->assertSame($root, $tool->getParent($role));
    }

    /**
     * @expectedException Skyline\Security\Exception\SecurityException
     * @depends testAddRole
     */
    public function testAddExistingRole() {
        $tool = $this->createTool();

        $root = $tool->getRole("SKYLINE");

        $tool->addRole("TEST", $root);
    }

    /**
     * @depends testAddRole
     */
    public function testUpdateRole() {
        $tool = $this->createTool();

        $role = $tool->getRole("SKYLINE.TEST");
        $this->assertEmpty($role->getDescription());
        $this->assertEquals(0, $role->getOptions());

        $this->assertTrue($tool->updateRole($role, NULL, "My Description", Role::OPTION_VISIBLE));

        $this->assertEquals(Role::OPTION_VISIBLE, $role->getOptions());
        $this->assertEquals("My Description", $role->getDescription());
    }

    /**
     * @depends testAddRole
     * @expectedException Skyline\Security\Exception\SecurityException
     */
    public function testRenameExistingRole() {
        $tool = $this->createTool();

        $role = $tool->getRole("SKYLINE.TEST");
        $tool->updateRole($role, "editor");
    }

    /**
     * @depends testAddRole
     */
    public function testRenameRole() {
        $tool = $this->createTool();

        $role = $tool->getRole("SKYLINE.TEST");
        $this->assertTrue($tool->updateRole($role, "OTHER_TEST"));

        $this->assertNull($tool->getRole("SKYLINE.TEST"));
        $this->assertEquals("SKYLINE.OTHER_TEST", $role->getRole());
    }

    /**
     * @depends testRenameRole
     * @expectedException Skyline\Security\Exception\SecurityException
     * @expectedExceptionCode 55
     */
    public function testRemoveRole() {
        $tool = $this->createTool();

        $role = $tool->getRole("SKYLINE.OTHER_TEST");
        $this->assertTrue($tool->removeRole($role));

        $tool->removeRole($role);
    }

    /**
     * @expectedException Skyline\Security\Exception\SecurityException
     * @expectedExceptionCode 56
     */
    public function testRemoveInternalRole() {
        $tool = $this->createTool();

        $role = $tool->getRole("SKYLINE.ADMIN");
        $tool->removeRole($role);
    }

    public function testHierarchie() {
        $tool = $this->createTool();

        $skyline = $tool->getRole("SKYLINE");
        $editor = $tool->getRole("SKYLINE.EDITOR");
        $translator = $tool->getRole("SKYLINE.EDITOR.TRANSLATOR");

        $this->assertSame($editor, $tool->getParent($translator));
        $this->assertSame($skyline, $tool->getParent($editor));
        $this->assertNull($tool->getParent($skyline));
    }
}
