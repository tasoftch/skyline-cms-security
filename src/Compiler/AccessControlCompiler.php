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

namespace Skyline\CMS\Security\Compiler;

use Skyline\Compiler\CompilerContext;
use Skyline\Expose\Compiler\AbstractAnnotationCompiler;
use Skyline\Compiler\CompilerConfiguration;

class AccessControlCompiler extends AbstractAnnotationCompiler
{
    public function compile(CompilerContext $context)
    {
        $access = [];

        foreach($this->yieldClasses("ACTIONCONTROLLER") as $controller) {
            $list = $this->findClassMethods($controller, self::OPT_PUBLIC_OBJECTIVE);

            if($list) {
                foreach($list as $name => $method) {
                    $annots = $this->getAnnotationsOfMethod($method, true);
                    if($annots) {
                        $roles = $annots["role"] ?? NULL;
                        if($roles) {
                            $access[$name]["r"] = $roles;
                        }
                        $relia = $annots["reliability"] ?? NULL;
                        if($relia) {
                            $rl = array_shift($relia);

                            if(count( $data = explode("::", $rl) ) == 2) {
                                $symbol = $data[0];
                                $cl = $this->qualifySymbol($data[0], $controller);
                                if($cl != $symbol) {
                                    $rl = eval("return $cl::$data[1];");
                                }
                            }

                            if($rl && is_numeric($rl))
                                $access[$name]["l"] = $rl;
                        }

                        if($users = $annots["user"] ?? NULL)
                            $access[$name]['u'] = $users;
                        if($groups = $annots["group"] ?? NULL)
                            $access[$name]['g'] = $groups;
                    }
                }
            }
        }
        $dir = $context->getSkylineAppDirectory(CompilerConfiguration::SKYLINE_DIR_COMPILED);

        $data = var_export($access, true);
        file_put_contents( "$dir/access-control.php", "<?php\nreturn $data;" );
    }
}