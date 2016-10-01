<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use DateTimeInterface;
use Lcobucci\JWT\Validation\ConstraintViolationException;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class IssuedBy implements Constraint
{
    /**
     * @var array
     */
    private $issuers;

    public function __construct(array $issuers)
    {
        $this->issuers = $issuers;
    }

    /**
     * {@inheritdoc}
     */
    public function validate(Token $token)
    {
        $issuer = $token->getClaim('iss');

        if (!in_array($issuer, $this->issuers, true)) {
            throw new ConstraintViolationException('The token was not issued by the given issuers');
        }
    }
}
