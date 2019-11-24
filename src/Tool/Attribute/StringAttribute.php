<?php

namespace Skyline\CMS\Security\Tool\Attribute;


class StringAttribute extends AbstractAttribute
{
    protected function convertValueFromDB($value)
    {
        return (string) $value;
    }

    protected function convertValueToDB($value)
    {
        return (string) $value;
    }
}