# JWT
[![Gitter](https://img.shields.io/badge/GITTER-JOIN%20CHAT%20%E2%86%92-brightgreen.svg?style=flat-square)](https://gitter.im/lcobucci/jwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Total Downloads](https://img.shields.io/packagist/dt/lcobucci/jwt.svg?style=flat-square)](https://packagist.org/packages/lcobucci/jwt)
[![Latest Stable Version](https://img.shields.io/packagist/v/lcobucci/jwt.svg?style=flat-square)](https://packagist.org/packages/lcobucci/jwt)

![Branch master](https://img.shields.io/badge/branch-master-brightgreen.svg?style=flat-square)
[![Build Status](https://img.shields.io/travis/lcobucci/jwt/master.svg?style=flat-square)](http://travis-ci.org/#!/lcobucci/jwt)
[![Scrutinizer Code Quality](https://img.shields.io/scrutinizer/g/lcobucci/jwt/master.svg?style=flat-square)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=master)
[![Code Coverage](https://img.shields.io/scrutinizer/coverage/g/lcobucci/jwt/master.svg?style=flat-square)](https://scrutinizer-ci.com/g/lcobucci/jwt/?branch=master)
[![SensioLabsInsight](https://insight.sensiolabs.com/projects/9c90ed7d-17de-4ba0-9ee0-3cf9c2f43f66/mini.png)](https://insight.sensiolabs.com/projects/9c90ed7d-17de-4ba0-9ee0-3cf9c2f43f66)

A simple library to work with JSON Web Token and JSON Web Signature based on the [RFC 7519](https://tools.ietf.org/html/rfc7519).

## Installation

Package is available on [Packagist](http://packagist.org/packages/lcobucci/jwt),
you can install it using [Composer](http://getcomposer.org).

```shell
composer require lcobucci/jwt
```

### Dependencies

- PHP 5.5+ (v3.2) and PHP 7 (v4.x)
- OpenSSL Extension

## Basic usage

**Important:** this is the documentation of our next major release (v4) and
it **WILL** change. If you are using the **stable** version you should
go to branch [3.2](https://github.com/lcobucci/jwt/blob/3.2/README.md).

### Creating

Just use the builder to create a new JWT/JWS tokens:

```php
use Lcobucci\JWT\Configuration;

$config = new Configuration(); // This object helps to simplify the creation of the dependencies
                               // instead of using "?:" on constructors.

$token = $config->createBuilder()
                ->issuedBy('http://example.com') // Configures the issuer (iss claim)
                ->canOnlyBeUsedBy('http://example.org') // Configures the audience (aud claim)
                ->withId('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
                ->issuedAt(time()) // Configures the time that the token was issue (iat claim)
                ->canOnlyBeUsedAfter(time() + 60) // Configures the time that the token can be used (nbf claim)
                ->expiresAt(time() + 3600) // Configures the expiration time of the token (exp claim)
                ->with('uid', 1) // Configures a new claim, called "uid"
                ->getToken(); // Retrieves the generated token


$token->getHeaders(); // Retrieves the token headers
$token->getClaims(); // Retrieves the token claims

echo $token->getHeader('jti'); // will print "4f1g23a12aa"
echo $token->getClaim('iss'); // will print "http://example.com"
echo $token->getClaim('uid'); // will print "1"
echo $token; // The string representation of the object is a JWT string (pretty easy, right?)
```

If we have multiple possible members in the audience of a given token, we can set multiple audience members like so:

```php
use Lcobucci\JWT\Configuration;

$config = new Configuration(); // This object helps to simplify the creation of the dependencies
                               // instead of using "?:" on constructors.

$token = $config->createBuilder()
                ->issuedBy('http://example.com')
                ->canOnlyBeUsedBy('http://example.org')
                ->canOnlyBeUsedBy('http://example.com')
                ->canOnlyBeUsedBy('http://example.io') // Sets all three as audience members of this token.
                ->withId('4f1g23a12aa', true)
                ->issuedAt(time())
                ->canOnlyBeUsedAfter(time() + 60)
                ->expiresAt(time() + 3600)
                ->with('uid', 1)
                ->getToken();
```

### Parsing from strings

Use the parser to create a new token from a JWT string (using the previous token as example):

```php
use Lcobucci\JWT\Configuration;

$config = new Configuration();
$token = $config->getParser()->parse((string) $token); // Parses from a string
$token->getHeaders(); // Retrieves the token header
$token->getClaims(); // Retrieves the token claims

echo $token->getHeader('jti'); // will print "4f1g23a12aa"
echo $token->getClaim('iss'); // will print "http://example.com"
echo $token->getClaim('aud')[0]; // will print "http://example.org"
echo $token->getClaim('uid'); // will print "1"
```

### Validating

We can easily validate if the token is valid (using the previous token as example):

```php
use Lcobucci\JWT\ValidationData;

$data = new ValidationData(); // It will use the current time to validate (iat, nbf and exp)
$data->issuedBy('http://example.com');
$data->canOnlyBeUsedBy('http://example.org');
$data->withId('4f1g23a12aa');

var_dump($token->validate($data)); // false, because token cannot be used before of now() + 60

$data->setCurrentTime(time() + 61); // changing the validation time to future

var_dump($token->validate($data)); // true, because current time is between "nbf" and "exp" claims

$data->setCurrentTime(time() + 4000); // changing the validation time to future

var_dump($token->validate($data)); // false, because token is expired since current time is greater than exp
```

If we have multiple possible issuers of an equivalent token, then it is possible to set multiple issuers to the ```ValidationData``` object:

```php
$data = new ValidationData();
$data->issuedBy(['http://example.com', 'http://example.io']);
$data->canOnlyBeUsedBy('http://example.org');
```

#### Important

- You have to configure ```ValidationData``` informing all claims you want to validate the token.
- If ```ValidationData``` contains claims that are not being used in token or token has claims that are not
configured in ```ValidationData``` they will be ignored by ```Token::validate()```.
- ```exp```, ```nbf``` and ```iat``` claims are configured by default in ```ValidationData::__construct()```
with the current UNIX time (```time()```).

## Token signature

We can use signatures to be able to verify if the token was not modified after its generation. This library implements Hmac, RSA and ECDSA signatures (using 256, 384 and 512).

### Important

Do not allow the string sent to the Parser to dictate which signature algorithm
to use, or else your application will be vulnerable to a [critical JWT security vulnerability](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries).

The examples below are safe because the choice in `Signer` is hard-coded and
cannot be influenced by malicious users.

### Hmac

Hmac signatures are really simple to be used:

```php
use Lcobucci\JWT\Configuration;

$config = new Configuration();
$signer = $config->getSigner(); // Default signer is HMAC SHA256

$token = $config->createBuilder()
                ->issuedBy('http://example.com') // Configures the issuer (iss claim)
                ->canOnlyBeUsedBy('http://example.org') // Configures the audience (aud claim)
                ->withId('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
                ->issuedAt(time()) // Configures the time that the token was issue (iat claim)
                ->canOnlyBeUsedAfter(time() + 60) // Configures the time that the token can be used (nbf claim)
                ->expiresAt(time() + 3600) // Configures the expiration time of the token (exp claim)
                ->with('uid', 1) // Configures a new claim, called "uid"
                ->sign($signer, 'testing') // creates a signature using "testing" as key
                ->getToken(); // Retrieves the generated token


var_dump($token->verify($signer, 'testing 1')); // false, because the key is different
var_dump($token->verify($signer, 'testing')); // true, because the key is the same
```

### RSA and ECDSA

RSA and ECDSA signatures are based on public and private keys so you have to generate using the private key and verify using the public key:

```php
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256; // you can use Lcobucci\JWT\Signer\Ecdsa\Sha256 if you're using ECDSA keys

$config = new Configuration();
$config->setSigner(new Sha256()); // Change the signer to RSA SHA256

$signer = $config->getSigner();
$privateKey = new Key('file://{path to your private key}');

$token = $config->createBuilder()
                ->issuedBy('http://example.com') // Configures the issuer (iss claim)
                ->canOnlyBeUsedBy('http://example.org') // Configures the audience (aud claim)
                ->withId('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
                ->issuedAt(time()) // Configures the time that the token was issue (iat claim)
                ->canOnlyBeUsedAfter(time() + 60) // Configures the time that the token can be used (nbf claim)
                ->expiresAt(time() + 3600) // Configures the expiration time of the token (exp claim)
                ->with('uid', 1) // Configures a new claim, called "uid"
                ->sign($signer,  $privateKey) // creates a signature using your private key
                ->getToken(); // Retrieves the generated token

$publicKey = new Key('file://{path to your public key}');

var_dump($token->verify($signer, $publicKey)); // true when the public key was generated by the private one =)
```

**It's important to say that if you're using RSA keys you shouldn't invoke ECDSA signers (and vice-versa), otherwise ```sign()``` and ```verify()``` will raise an exception!**

## Security

Because of the awesome guys of [Paragon Initiative](https://paragonie.com) and the
PHP community's support we had a security audit for this library (thanks a lot guys)!

Check the result [here](https://paragonie.com/audit/UGCwpFmaIkQ085l7)!
