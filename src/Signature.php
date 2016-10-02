<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

/**
 * This class represents a token signature
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Signature
{
    /**
     * @var string
     */
    private $hash;

    /**
     * @var string
     */
    private $payload;

    public function __construct(string $hash, string $payload)
    {
        $this->hash = $hash;
        $this->payload = $payload;
    }

    public function hash(): string
    {
        return $this->hash;
    }

    /**
     * Returns the signature payload as a string representation of the signature
     */
    public function __toString(): string
    {
        return $this->payload;
    }
}
