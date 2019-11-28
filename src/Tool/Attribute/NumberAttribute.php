<?php

namespace Skyline\CMS\Security\Tool\Attribute;


class NumberAttribute extends StringAttribute
{
    public function convertValueFromDB($value)
    {
        return parent::convertValueFromDB($value) * 1;
    }
}