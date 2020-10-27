# JSON Web Tokens (JWT) implementation for PHP 7

## JWT

Read more about JWT here:

* [RFC 7519](https://tools.ietf.org/html/rfc7519)
* [jwt.io](https://jwt.io/introduction/)
* [JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook)

## License

Please check [BSD-3 Clause](http://opensource.org/licenses/BSD-3-Clause) terms before use.

## Supported algorithms

* HS256
* HS384
* HS512
* RS256
* RS384
* RS512

## Installation

You can add this package to your project by running composer command:
```
composer require nowakowskir/php-jwt
```

Make sure your vendor auto load file is loaded correctly and the following classes are used.

```
use Nowakowskir\JWT\JWT;
use Nowakowskir\JWT\TokenDecoded;
use Nowakowskir\JWT\TokenEncoded;
```

## Elements

When using this package, you will be mostly using two classes: ```TokenEncoded``` and ```TokenDecoded```.

You can transform objects of those class like below:

```
TokenEncoded => TokenDecoded
TokenDecoded => TokenEncoded
```


### TokenDecoded

This class is a representation of a decoded token. It consists of a header and payload. Both elements are arrays.

Token represented by an object of ```TokenDecoded``` class lets you access and modify any of its parts.

### TokenEncoded

This class is a representation of an encoded token.

## Usage

### Building the new JWT

There are two arguments you can optionally pass to ```TokenDecode``` constructor. These are payload and header.

```
$tokenDecoded = new TokenDecoded(['payload_key' => 'value'], ['header_key' => 'value']);
$tokenEncoded = $tokenDecoded->encode($privateKey, JWT::ALGORITHM_RS256);

echo 'Your token is: ' . $tokenEncoded->toString();
```

> Please check *Security best practices* section to understand why providing algorithm is mandatory when encoding a token!

### Instantiating existing token

```
$tokenEncoded = new TokenEncoded('Existing JSON Web Token');
```

### Getting token's header

```
$tokenEncoded = new TokenEncoded('Existing JSON Web Token');
$header = $tokenEncoded->decode()->getHeader();
```

### Getting token's payload

```
$tokenEncoded = new TokenEncoded('Existing JSON Web Token');
$payload = $tokenEncoded->decode()->getPayload();
```

> Please note that providing a key is not required to decode a token, as its header and payload are public. You should put special attention to not pass any confidential information within the token's header and payload. JWT only allows you to verify if the token containing the given payload was issued by a trusted party. It does not protect your data passed in a payload! Be aware anybody can access your token's payload!

### Validating token

In order to use a decoded payload make sure your token goes through validate process first. Otherwise, payload can't be assumed as trusted!

```
try {
    $tokenEncoded->validate($publicKey, JWT::ALGORITHM_RS256);
} catch(Exception $e) {
    // Token validation failed.
}
```

> Please check the the *Security best practices* section to understand why providing an algorithm is mandatory when validating a token!

If you need more detailed information about why your validation process has failed, there are several exception classes you can catch:

Exception Class | Description
------------ | -------------
``Nowakowskir\JWT\Exceptions\IntegrityViolationException`` | Token is not trusted. Either an invalid key was provided or a token was tampered.
``Nowakowskir\JWT\Exceptions\AlgorithmMismatchException`` | If the algorithm you decided to use to validate the token is different from the algorithm specified in the token's header.
``Nowakowskir\JWT\Exceptions\TokenExpiredException`` | Token has expired (if ```exp``` was set by issuer).
``Nowakowskir\JWT\Exceptions\TokenInactiveException`` | Token is not yet active (if ```nbf``` was set by issuer).


### Building the new JWT with expiration date (exp)

If you want your token to expire at some date, you can use ```exp``` flag.

```
$tokenDecoded = new TokenDecoded(['exp' => time() + 1000]);
$tokenEncoded = $tokenDecoded->encode($key, JWT::ALGORITHM_RS256);
```

### Building the new JWT with not before date (nbf)

If you want your token to be not active until reach some date, you can use ```nbf``` flag.

```
$tokenDecoded = new TokenDecoded(['nbf' => time() + 1000]);
$tokenEncoded = $tokenDecoded->encode($key, JWT::ALGORITHM_RS256);
```

### Solving clock difference issue between servers (exp, nbf)

Because the clock may vary across the servers, you can use so-called ``leeway`` to solve this issue. It's some kind of time margin which will be taken into account when validating token (exp, nbf).

```
$leeway = 500;
$tokenEncoded = new TokenEncoded('Existing JSON Web Token');
$tokenEncoded->validate($key, JWT::ALGORITHM_RS256, $leeway);
```

## Security best practices

### Don't pass confidential data in token's payload

Please note that providing a key is not required to decode a token, as its header and payload are public. You should put special attention to not pass any confidential information within the token's header and payload. JWT only allows you to verify if the token containing the given payload was issued by a trusted party. It does not protect your data passed in a payload! Be aware anybody can access your token's payload!

### Don't trust your payload until you validate a token

The only way to ensure the token is valid is to use ```TokenEncoded::validate()``` method. Please keep in mind that ```TokenDecoded::decode()``` method decodes a token only. It gives you access to its payload without any validation!

The reason why it allows you to get the token's payload without any validation is that:

* it's a nature of JWT that token's payload is not encrypted and is not protected by keys, so you should not even have illusion it is protected,
* you may need to use some parts of your token's payload before token validation.

### Enforce algorithm when encoding and validating token

As in some circumstances, the algorithm defined in token's header may be modified by an attacker, it's highly recommended to not rely on the algorithm contained in token's header.

Due to security reasons you should choose one algorithm whenever possible and stick to it in both issuer and verifier applications.

To increase your tokens' security, this package requires an algorithm to be provided when encoding and validating tokens.

Below you can find correct way of encoding and decoding tokens:

```
// Issuer
$tokenDecoded = new TokenDecoded();
$tokenEncoded = $tokenDecoded->encode($privateKey, JWT::ALGORITHM_RS256);
```

```
// Consumer
$tokenEncoded->validate($publicKey, JWT::ALGORITHM_RS256);
```

As you can see, both use the same algorithm.

This package throws ```Nowakowskir\JWT\Exceptions\AlgorithmMismatchException``` if the algorithm you decided to use to validate the token is different from the algorithm specified in the token's header.

This protects your token against successful validation in case the token has been tampered.

You may be tempted to do some workaround and use the algorithm contained in the token's header for validation purposes, although it's highly not recommended!

```
// Don't use algorithm defined in token's header like here!
$header = $tokenEncoded->decode()->getHeader();
$tokenEncoded->validate($publicKey, $header['alg']);
```

### Using insecure tokens

Creating insecure tokens is not possible due to security reasons.

This package does not let you create a token with ```none``` algorithm or empty signature.

Trying to do so will result in ```Nowakowskir\JWT\Exceptions\InsecureTokenException``` exception.

```
try {
    $tokenEncoded = new TokenEncoded('Existing JSON Web Token with none algorithm or missing signature');
} catch (InsecureTokenException $e) {
    // Insecure token
}
```

```
try {
    $tokenDecoded = new TokenDecoded();

    $tokenDeoded->encode($privateKey, 'none');
} catch (InsecureTokenException $e) {
    // Insecure token
}
```

It's also not possible to parse token without an algorithm defined.

```
try {
    $tokenEncoded = new TokenEncoded('Existing JSON Web Token without an algorithm');
} catch (UndefinedAlgorithmException $e) {
    // Algorithm not provided
}
```


### Generate a strong private key

First, you need to generate a private key.

```
ssh-keygen -t rsa -b 4096 -m PEM -f private.key
chmod 600 private.key
```

Next, you need to generate a public key based on the private key.

```
openssl rsa -in private.key -pubout -outform PEM -out public.pub
```

### Rotate your public/private key pair regularly

To minimize the risk of gaining your public/private key by an unauthorized entity, rotate it regularly.

### Protect your private key

Make sure your private key is secured and not accessible by any unauthorized entities. Special care should be taken to file permissions. In most cases, you should set ```600``` permissions on your private key file, which means it's accessible only by the file's owner.

### Protect your public key

Even if it's called public, try to share this key only when it's really required. Also, file permissions should be as restrictive as possible. Do not pass public keys between requests or expose them to the public audience.

### Don't pass tokens in URL

They will be stored in server logs, browser history, etc.

### Use token's expiration date

Whenever possible, use the token's expiration date, so the token is valid as short as necessary.

### Check for updates

Regularly check for updates of this package.