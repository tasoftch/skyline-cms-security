<?php

namespace Skyline\CMS\Security\Tool\Attribute\Value;


class FileValueContainer extends ValueContainer
{
    private $filename;

    /**
     * @return mixed
     */
    public function getFilename()
    {
        return $this->filename;
    }

    /**
     * @param mixed $filename
     */
    public function setFilename($filename): void
    {
        $this->filename = $filename;
    }
}