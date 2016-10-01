<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use OutOfBoundsException;

final class DataSet
{
    /**
     * @var array
     */
    private $data;

    /**
     * @var string
     */
    private $payload;

    public function __construct(array $data, string $payload)
    {
        $this->data = $data;
        $this->payload = $payload;
    }

    public function get(string $name, $default = null)
    {
        if ($this->has($name)) {
            return $this->data[$name];
        }

        if ($default === null) {
            throw new OutOfBoundsException();
        }

        return $default;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->data);
    }

    public function __toString(): string
    {
        return $this->payload;
    }
}
