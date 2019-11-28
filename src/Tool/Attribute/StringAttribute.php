<?php

namespace Skyline\CMS\Security\Tool\Attribute;


class StringAttribute extends AbstractAttribute
{
    public function convertValueFromDB($value)
    {
        return (string) $value;
    }

    public function convertValueToDB($value)
    {
        return (string) $value;
    }
}