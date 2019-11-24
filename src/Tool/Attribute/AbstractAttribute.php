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

namespace Skyline\CMS\Security\Tool\Attribute;


abstract class AbstractAttribute
{
    /** @var int */
    private $id;
    /** @var string */
    private $name;
    /** @var mixed */
    private $value;
    /** @var string|null */
    private $description;
    /** @var string|null */
    private $icon;
    /** @var int */
    private $options;

    public function __construct($record)
    {
        $this->id = $record["id"] * 1;
        $this->options = $record["options"] * 1;
        $this->value = $this->convertValueFromDB( $record["value"] );
        $this->description = $record["description"];
        $this->icon = $record["icon"];
        $this->name = $record["name"];
    }

    /**
     * Tries to get an attribute from valueType field
     *
     * @param $record
     * @return static|null
     */
    public static function create($record) {
        $class = NULL;
        
        switch ($record["valueType"]) {
            case "string":
            case "string<uri>":
            case "string<url>":
            case "string<email>":
                $class = StringAttribute::class; break;
            case "text":
                $class = TextAttribute::class; break;
            case "date":
                $class = DateAttribute::class; break;
            case 'time':
                $class = TimeAttribute::class; break;
            case 'datetime':
                $class = DateTimeAttribute::class; break;
            default:
                if(class_exists($record["valueType"]))
                    $class = ObjectAttribute::class;
        }

        if($class)
            return new $class($record);
        return NULL;
    }

    /**
     * Called to store the attribute in data base
     * @return mixed
     */
    public function getDataBaseValue() {
        return $this->convertValueToDB($this->getValue());
    }

    /**
     * Called on creation from data base
     *
     * @param mixed $value
     * @return mixed
     */
    abstract protected function convertValueFromDB($value);

    /**
     * Called to convert the value to the data base
     *
     * @param $value
     * @return mixed
     */
    abstract protected function convertValueToDB($value);

    /**
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @return string|null
     */
    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * @return string|null
     */
    public function getIcon(): ?string
    {
        return $this->icon;
    }

    /**
     * @return int
     */
    public function getOptions(): int
    {
        return $this->options;
    }
}