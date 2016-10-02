<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class SignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signature::__construct
     */
    public function constructorMustConfigureAttributes()
    {
        $signature = new Signature('test', 'payload');

        self::assertAttributeEquals('test', 'hash', $signature);
        self::assertAttributeEquals('payload', 'payload', $signature);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signature::__construct
     *
     * @covers \Lcobucci\JWT\Signature::__toString
     */
    public function toStringMustReturnTheHash()
    {
        $signature = new Signature('test', 'payload');

        self::assertEquals('payload', (string) $signature);
    }
}
