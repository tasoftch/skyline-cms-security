<?php

namespace Skyline\CMS\Security\UserSystem;


class Role extends \Skyline\Security\Role\Role
{
    const OPTION_INTERNAL = 1<<0;
    const OPTION_ASSIGNABLE = 1<<1;
    const OPTION_VISIBLE = 1<<2;
    const OPTION_FINAL = 1<<3;
}