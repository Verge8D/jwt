<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class UnsignedTokenTest extends \PHPUnit_Framework_TestCase
{
    const CURRENT_TIME = 100000;

    /**
     * @var Configuration
     */
    private $config;

    /**
     * @before
     */
    public function createConfiguration()
    {
        $this->config = new Configuration();
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     */
    public function builderCanGenerateAToken()
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->createBuilder();

        $token = $builder->withId('1')
                         ->canOnlyBeUsedBy('http://client.abc.com')
                         ->issuedBy('http://api.abc.com')
                         ->expiresAt(self::CURRENT_TIME + 3000)
                         ->with('user', $user)
                         ->getToken();

        self::assertAttributeEquals(null, 'signature', $token);
        self::assertEquals(['http://client.abc.com'], $token->getClaim('aud'));
        self::assertEquals('http://api.abc.com', $token->getClaim('iss'));
        self::assertEquals(self::CURRENT_TIME + 3000, $token->getClaim('exp'));
        self::assertEquals($user, $token->getClaim('user'));

        return $token;
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     */
    public function parserCanReadAToken(Token $generated)
    {
        $read = $this->config->getParser()->parse((string) $generated);

        self::assertEquals($generated, $read);
        self::assertEquals('testing', $read->getClaim('user')['name']);
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\ValidationData
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Claim\EqualsTo
     * @covers \Lcobucci\JWT\Claim\GreaterOrEqualsTo
     * @covers \Lcobucci\JWT\Claim\ContainedEqualsTo
     * @covers \Lcobucci\JWT\Claim\ContainsEqualsTo
     */
    public function tokenValidationShouldReturnWhenEverythingIsFine(Token $generated)
    {
        $data = new ValidationData(self::CURRENT_TIME - 10);
        $data->setAudience('http://client.abc.com');
        $data->setIssuer('http://api.abc.com');

        self::assertTrue($generated->validate($data));
    }

    /**
     * @test
     *
     * @dataProvider invalidValidationData
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\ValidationData
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Claim\EqualsTo
     * @covers \Lcobucci\JWT\Claim\GreaterOrEqualsTo
     * @covers \Lcobucci\JWT\Claim\ContainedEqualsTo
     * @covers \Lcobucci\JWT\Claim\ContainsEqualsTo
     */
    public function tokenValidationShouldReturnFalseWhenExpectedDataDontMatch(ValidationData $data, Token $generated)
    {
        self::assertFalse($generated->validate($data));
    }

    public function invalidValidationData()
    {
        $expired = new ValidationData(self::CURRENT_TIME + 3020);
        $expired->setAudience('http://client.abc.com');
        $expired->setIssuer('http://api.abc.com');

        $invalidAudience = new ValidationData(self::CURRENT_TIME - 10);
        $invalidAudience->setAudience('http://cclient.abc.com');
        $invalidAudience->setIssuer('http://api.abc.com');

        $invalidIssuer = new ValidationData(self::CURRENT_TIME - 10);
        $invalidIssuer->setAudience('http://client.abc.com');
        $invalidIssuer->setIssuer('http://aapi.abc.com');

        return [[$expired], [$invalidAudience], [$invalidIssuer]];
    }
}
