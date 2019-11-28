<?php

namespace Skyline\CMS\Security\UserSystem;


use Skyline\PDO\PDOResourceInterface;

class Group implements PDOResourceInterface
{
    const OPTION_INTERNAL = 1<<0;

    /** @var int */
    private $id;
    /** @var string */
    private $name;
    /** @var string|null */
    private $description;
    /** @var int */
    private $options;
    /** @var bool */
    private $internal = false;

    /**
     * Group constructor.
     * @param int $id
     * @param string $name
     * @param string|null $description
     * @param int $options
     */
    public function __construct($record)
    {
        $this->id = $record["id"] * 1;
        $this->name = $record["name"];
        $this->description = $record["description"] ?: NULL;
        $this->options = $record["options"] * 1;

        if($this->options & self::OPTION_INTERNAL)
            $this->internal = true;
        $this->options &= ~self::OPTION_INTERNAL;
    }


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
     * @return string|null
     */
    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * @return int
     */
    public function getOptions(): int
    {
        return $this->options;
    }

    /**
     * @return bool
     */
    public function isInternal(): bool
    {
        return $this->internal;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->getName();
    }
}