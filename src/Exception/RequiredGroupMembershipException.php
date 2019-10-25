<?php

namespace Skyline\CMS\Security\Exception;


use Skyline\Security\Exception\SecurityException;
use Skyline\Security\Exception\UserNotFoundException;

class RequiredGroupMembershipException extends UserNotFoundException
{
}