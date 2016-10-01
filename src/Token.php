<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use DateTime;
use DateTimeInterface;
use Lcobucci\JWT\Signer\Key;
use OutOfBoundsException;

/**
 * Basic structure of the JWT
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Token
{
    /**
     * The token headers
     *
     * @var DataSet
     */
    private $headers;

    /**
     * The token claim set
     *
     * @var DataSet
     */
    private $claims;

    /**
     * The token signature
     *
     * @var Signature|null
     */
    private $signature;

    /**
     * Initializes the object
     *
     * @param DataSet $headers
     * @param DataSet $claims
     * @param Signature|null $signature
     */
    public function __construct(
        DataSet $headers,
        DataSet $claims,
        Signature $signature = null
    ) {
        $this->headers = $headers;
        $this->claims = $claims;
        $this->signature = $signature;
    }

    /**
     * Returns the token headers
     */
    public function headers(): DataSet
    {
        return $this->headers;
    }

    /**
     * Returns the token claim set
     */
    public function claims(): DataSet
    {
        return $this->claims;
    }

    /**
     * @return Signature|null
     */
    public function signature()
    {
        return $this->signature;
    }

    /**
     * Verify if the key matches with the one that created the signature
     *
     * @param Signer $signer
     * @param Key $key
     *
     * @return bool
     */
    public function verify(Signer $signer, Key $key): bool
    {
        if ($this->signature === null || $this->headers['alg'] !== $signer->getAlgorithmId()) {
            return false;
        }

        return $this->signature->verify($signer, $this->getPayload(), $key);
    }

    /**
     * Determine if the token is expired.
     *
     * @param DateTimeInterface $now Defaults to the current time.
     *
     * @return bool
     */
    public function isExpired(DateTimeInterface $now = null)
    {
        $exp = $this->claims()->get('exp', false);

        if ($exp === false) {
            return false;
        }

        $now = $now ?: new DateTime();

        $expiresAt = new DateTime();
        $expiresAt->setTimestamp($exp);

        return $now > $expiresAt;
    }

    /**
     * Returns the token payload
     *
     * @return string
     */
    public function getPayload(): string
    {
        return $this->payload[0] . '.' . $this->payload[1];
    }

    /**
     * Returns an encoded representation of the token
     *
     * @return string
     */
    public function __toString(): string
    {
        $data = implode('.', $this->payload);

        if ($this->signature === null) {
            $data .= '.';
        }

        return $data;
    }
}
