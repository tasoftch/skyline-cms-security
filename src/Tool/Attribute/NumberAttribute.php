<?php

namespace Skyline\CMS\Security\Tool\Attribute;


class NumberAttribute extends StringAttribute
{
    protected function convertValueFromDB($value)
    {
        return parent::convertValueFromDB($value) * 1;
    }
}