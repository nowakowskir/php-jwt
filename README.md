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

```
composer require nowakowskir/php-jwt
```

## Elements

When using this package, you will be mostly interested in two classes: ```TokenEncoded``` and ```TokenDecoded```.

### TokenDecoded

This class is representation of decoded token. It consist of header and payload.

You can get decoded token from your encoded token using ```$tokenEncoded->decode()```. In result, you will get new object of ```TokenDecoded``` class.

> Please note that providing key is not required to decode token as its header and payload are public. Read more about this in *Security best practices section*!


### TokenEncoded

This class is representation of encoded token. 

If you want to create encoded token, you just need to prepare decoded version of token first and then use ```$tokenDecoded->encode($key)``` method. In result, you will get new object of ```TokenEncoded``` class.

You may also want to create encoded token directly from a string, so you can use ```$tokenEncoded = new TokenEncoded($tokenString)```.

You should use ```$tokenEncoded->decode()``` method together with ```$tokenEncoded->validate($key)```.

In order to use the decoded payload make sure your token goes through validate process first. Otherwise, payload can not be treated as trusted!

## Security best practices

## Don't pass confidental data in token's payload

Please note that providing key is not required to decode token as its header and payload are public. You should take care not to pass any confidental information within token's header and payload. JWT only allows you to verify, if the token containing given payload was issued by trusted party. It does not protect your data passed in payload!

## Don't trust your payload until you validate token

The only way of ensuring the token is valid is to use ```validate()``` method on encoded token. Please keep in mind that ```decode()``` method decodes the token and gives you access to its payload without any validation.

## Enforce algorithm when encoding and validating token

Due to security reasons you should choose one algorithm whenever possible and stick to it in both issuer and verifier applications enforcing selected algorithm to be used when encoding and validating token.

```
$tokenDecoded = new TokenDecoded([], []);
$tokenEndcoded = $tokenDecoded->encode($privateKey, JWT::ALGORITHM_RS256);
```

```
$tokenEncoded = new TokenEncoded($tokenString);
try {
    $tokenEncoded->validate($publicKey, JWT::ALGORITHM_RS256);
} catch (IntegrityViolationException $e) {
    // Token not trusted
}
```

Algorithm defined in token's header may be tampered on the way which in some circumstances may allow an attacker to successfuly validate a tampered token!

## Generate strong private key

Follow the instructions below to generate strong private key.

## Protect your private key

Make sure your private key is secured and not accessible by any unauthorized entities. Special care should be taken to file permissions. In most cases you should set ```600``` permission on your private key file, which means it's accessible only by file's owner.

## Protect your public key

Even if it's called public, try to share this key only when it's really necessary to do so. Also file permissions should be as restrictive as possible. Do not pass public key between requests or expose it publicly.

## Use token's expiration date

Whenever possible, use token's expiration date so it's valid as short as necessary.

## Unsecured tokens

Creating unsecured tokens is not possible due to security reasons. Using this library you can not create a token with ```none``` algorithm or empty signature. Trying to create such token will throw ```UnsecureTokenException```.

```
// Token with missing signature
$tokenString = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyMTIzIiwic2Vzc2lvbiI6ImNoNzJnc2IzMjAwMDB1ZG9jbDM2M2VvZnkiLCJuYW1lIjoiUHJldHR5IE5hbWUiLCJsYXN0cGFnZSI6Ii92aWV3cy9zZXR0aW5ncyJ9.'

try {
$tokenEncoded = new TokenEncoded($tokenString);
} catch (UnsecureTokenException $e) {
    // Unsecure token
}
```

```
// Crafted token with none algorithm
$header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => 'none']));
$payload = Base64Url::encode(json_encode([]));
$signature = Base64Url::encode('signature');
        
$tokenString = sprintf('%s.%s.%s', $header, $payload, $signature);

try {
    $tokenEncoded = $tokenEncoded($tokenString);
} catch (UnsecureTokenException $e) {
    // Unsecure token
}
```

```
// Creating token with none algorithm
$tokenDecoded = new TokenDecoded(['alg' => 'none'], []);

try {
    $tokenEncoded = $tokenDecoded->encode($key);
} catch (UnsecureTokenException $e) {
    // Unsecure token
}
```

### Check for updates

Regularly check for updates of this library. 

## Usage

### Creating new token

```
$tokenDecoded = new TokenDecoded($header, $payload);
$tokenEncoded = $tokenDecoded->encode($key);

echo 'Your token is: ' . $tokenEncoded->__toString();
```

### Validating existing token

```
$tokenEncoded = new TokenEncoded('eyJhbGciOiJI...2StJdy+4XC3kM=');
        
try {
    $tokenEncoded->validate($key);
} catch (IntegrityViolationException $e) {
    // Token is not trusted
} catch(TokenExpiredException $e) {
    // Token expired (exp date reached)
} catch(TokenInactiveException $e) {
    // Token is not yet active (nbf date not reached)
} catch(Exception $e) {
    // Something else gone wrong
}
```

### Getting payload of existing token

```
$tokenEncoded = new TokenEncoded('eyJhbGciOiJI...2StJdy+4XC3kM=');

var_dump($tokenEncoded->decode()->getPayload());
```

> Please note that providing key is not required to decode token, as its header and payload are public. You should take care not to pass any confidental information within token's header and payload. JWT only allows you to verify, if the token containing given payload was
issued by trusted party. It does not protect your data passed in payload!

### Creating new token with custom algorithm

By default ```HS256``` algorithm is used to encode tokens. You can change algorithm by either by providing it under ```alg``` key in token's header or as a parameter to ```encode()``` method. Because it's possible to provide algorithm in two places, algorithm defined in ```encode()``` method takes priority if provided in both places.

```
$tokenDecoded = new TokenDecoded(['alg' => JWT::ALGORITHM_HS384], $payload);
$tokenEncoded = $tokenDecoded->encode($key);
```

```
$tokenDecoded = new TokenDecoded([], $payload);
$tokenEncoded = $tokenDecoded->encode($key, JWT::ALGORITHM_HS384);
```

```
$tokenDecoded = new TokenDecoded(['alg' => JWT::ALGORITHM_HS384], $payload);
$tokenEncoded = $tokenDecoded->encode($key, JWT::ALGORITHM_HS512);
// HS512 algorithm will take priority
```

Please note that there is no need to provide algorithm when validating token as algorithm is already contained in token's header, although for security reasons it's highly recommended to do so!

Less secure solution but with more flexibility:

```
$tokenEncoded = new TokenEncoded($tokenString);
$tokenEncoded->validate($key);
```

More secure solution but with less flexibility:

```
$tokenEncoded = new TokenEncoded($tokenString);
$tokenEncoded->validate($publicKey, JWT::ALGORITHM_RS256);
```

### Using private/public key pair to sign and validate token

First you need to generate private key.

```
ssh-keygen -t rsa -b 4096 -m PEM -f private.key
chmod 600 private.key
```

Next, you need to generate public key based on private key.

```
openssl rsa -in private.key -pubout -outform PEM -out public.pub
```

Private key will be used to sign a token whereas public key will be used to verify a token.

```
$tokenDecoded = new TokenDecoded();
$privateKey = file_get_contents('./private.key');
$tokenEncoded = $tokenDecoded->encode($privateKey, JWT::ALGORITHM_RS256);

$tokenString = $tokenEncoded->__toString();
```

```
$publicKey = file_get_contents('./public.pub');
$tokenEncoded = new TokenEncoded($tokenString);

try {
    $tokenEncoded->validate($key);
} catch (IntegrityViolationException $e) {
    // Token is not trusted
}
```

### Creating new token with expiration date (exp)

You may need to define expiration date for your token. To do so, you need to provide timestamp of expiration date into token's payload under ```exp``` key.

```
$tokenDecoded = new TokenDecoded([], ['exp' => time() + 1000]);
$tokenEncoded = $tokenDecoded->encode($key);
```

### Creating new token with not before date (nbf)

You may need to define date before which your token should not be valid. To do so, you need to provide timestamp of not before date into token's payload under ```nbf``` key.

```
$tokenDecoded = new TokenDecoded([], ['nbf' => time() + 1000]);
$tokenEncoded = $tokenDecoded->encode($key);
```

### Solving clock differences issue between servers (exp, nbf)

Because clock may vary across the servers, you can use so called ```leeway``` to solve this issue. It's some kind of margin which will be taken into account when validating token (```exp```, ```nbf```).

```
$leeway = 500;
$tokenEncoded = new TokenEncoded($tokenString);
$tokenEncoded->validate($key, $leeway);
```

## Sample

### Application

Let's imagine we have API that is used by our frontend application, so we have two parties: API and frontend application.

You don't want to use cookies as your API is hosted on other domain and session is not shared across the servers. Passing user credentials in the API requests is also not a good idea. We need some other way of verification. Here JWT comes into play.

Your frontend application can generate JWT token containing some payload and sign it using some key. Token will be appended to the request's headers under ```Authentication``` key. Token's payload is public and can be easily read. It's not encrypted itself. All JWT does in this case is just signing the token with given key, assuring our API application that given payload has been signed by trusted party and was not tampered on the way.

Let's see how we can implement interaction between those two applications.

> Be aware that the following demonstrations are not meant to be used in production. These samples are for educational purposes only and thus remain simple.

### Frontend

```
$payload = ['name' => 'john'];

$tokenDecoded = new TokenDecoded([], $payload);

$privateKey = file_get_contents('./private.key');

$tokenEncoded = $tokenDecoded->encode($privateKey, JWT::ALGORITHM_RS256);

$opts = [
    'http' => [
        'method' => 'GET',
        'header' => 'Authentication: ' . $tokenEncoded->__toString() . "\r\n",
    ]];

$context = stream_context_create($opts);

$response = file_get_contents('http://localhost/api/welcome', false, $context);

echo $response;
```

### API

```
if (! array_key_exists('HTTP_AUTHENTICATION', $_SERVER)) {
    // Handle no authentication header received
}

try {
    $tokenEncoded = new TokenEncoded($_SERVER['HTTP_AUTHENTICATION']);
} catch (Exception $e) {
    // Handle token parsing exceptions
}

$publicKey = file_get_contents('./public.pub');

try {
    $tokenEncoded->validate($publicKey, JWT::ALGORITHM_RS256);
} catch (IntegrityViolationException $e) {
    // Handle token not trusted
} catch (Exception $e) {
    // Handle other validation exceptions
}

$tokenDecoded = $tokenEncoded->decode();

$payload = $tokenDecoded->getPayload();

header('Content-Type: application/json');

echo json_encode([
    'name' => $payload['name'] ?? 'unknown',
]);
```
