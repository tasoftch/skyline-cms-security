<?php

namespace Skyline\CMS\Security\Tool\Attribute\Value;


class Address implements AttributeValueInterface
{
    const TYPE_PRIVATE = 1;
    const TYPE_WORK = 2;

    /** @var int */
    private $type;
    /** @var string */
    private $street;
    /** @var int|string */
    private $zip;
    /** @var string|null */
    private $district;
    /** @var string|null */
    private $city;
    /** @var string|null */
    private $country;

    /**
     * @return int
     */
    public function getType(): int
    {
        return $this->type;
    }

    /**
     * @param int $type
     */
    public function setType(int $type): void
    {
        $this->type = $type;
    }

    /**
     * @return string
     */
    public function getStreet(): string
    {
        return $this->street;
    }

    /**
     * @param string $street
     */
    public function setStreet(string $street): void
    {
        $this->street = $street;
    }

    /**
     * @return int|string
     */
    public function getZip()
    {
        return $this->zip;
    }

    /**
     * @param int|string $zip
     */
    public function setZip($zip): void
    {
        $this->zip = $zip;
    }

    /**
     * @return null|string
     */
    public function getDistrict(): ?string
    {
        return $this->district;
    }

    /**
     * @param null|string $district
     */
    public function setDistrict(?string $district): void
    {
        $this->district = $district;
    }

    /**
     * @return null|string
     */
    public function getCity(): ?string
    {
        return $this->city;
    }

    /**
     * @param null|string $city
     */
    public function setCity(?string $city): void
    {
        $this->city = $city;
    }

    /**
     * @return null|string
     */
    public function getCountry(): ?string
    {
        return $this->country;
    }

    /**
     * @param null|string $country
     */
    public function setCountry(?string $country): void
    {
        $this->country = $country;
    }

    public function serialize()
    {
        return serialize([
            $this->type,
            $this->street,
            $this->zip,
            $this->district,
            $this->city,
            $this->country
        ]);
    }

    public function unserialize($serialized)
    {
        list(
            $this->type,
            $this->street,
            $this->zip,
            $this->district,
            $this->city,
            $this->country
            ) = unserialize($serialized);
    }
}