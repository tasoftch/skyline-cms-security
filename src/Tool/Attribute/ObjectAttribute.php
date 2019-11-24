<?php

namespace Skyline\CMS\Security\Tool\Attribute;


class ObjectAttribute extends AbstractAttribute
{
    protected function convertValueFromDB($value)
    {
        return unserialize($value);
    }

    protected function convertValueToDB($value)
    {
        return serialize($value);
    }
}