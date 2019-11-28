<?php

namespace Skyline\CMS\Security\Tool\Attribute;


class ObjectAttribute extends AbstractAttribute
{
    public function convertValueFromDB($value)
    {
        return unserialize($value);
    }

    public function convertValueToDB($value)
    {
        return serialize($value);
    }
}