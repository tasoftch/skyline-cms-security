<?php

namespace Skyline\CMS\Security\UserSystem;


use Skyline\PDO\PDOResourceInterface;

class Role extends \Skyline\Security\Role\Role implements PDOResourceInterface
{
    const OPTION_INTERNAL = 1<<0;
    const OPTION_ASSIGNABLE = 1<<1;
    const OPTION_VISIBLE = 1<<2;
    const OPTION_FINAL = 1<<3;

    /** @var int */
    private $id;
    /** @var string|null */
    private $description;
    /** @var bool */
    private $internal;
    /** @var int */
    private $options;

    public function __construct($data)
    {
        parent::__construct($data["role"]);
        $this->description = $data["description"];
        $this->id = $data["id"]*1;
        $this->options = $data["options"] * 1;
        $this->internal = $this->options & self::OPTION_INTERNAL ? true : false;
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
     * @return string|null
     */
    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * @return bool
     */
    public function isInternal(): bool
    {
        return $this->internal;
    }

    /**
     * @return int
     */
    public function getOptions(): int
    {
        return $this->options;
    }
}