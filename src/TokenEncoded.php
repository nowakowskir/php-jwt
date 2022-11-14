<?php

namespace Nowakowskir\JWT;

/**
 * This class is representation of encoded JSON Web Token (JWT).
 *
 * @author   Radosław Nowakowski <nowakowski.r@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/nowakowskir/php-jwt
 */
class TokenEncoded
{
    /**
     * String representation of the encoded token.
     */
    protected $token;
    
    /**
     * Base64 url encoded representation of JSON encoded token's header.
     */
    protected $header;
    
    /**
     * Base64 url encoded representation of JSON encoded token's payload.
     */
    protected $payload;
    
    /**
     * Base64 url encoded representation of token's signature.
     */
    protected $signature;

    /**
     * @param string $token
     * 
     * @throws EmptyTokenException
     */
    public function __construct(string $token)
    {
        Validation::checkTokenStructure($token);
        
        $elements = explode('.', $token);
        list($header, $payload, $signature) = $elements;
        
        $headerArray = json_decode(Base64Url::decode($header), true);
        $payloadArray = json_decode(Base64Url::decode($payload), true);
        
        Validation::checkAlgorithmDefined($headerArray);
        Validation::checkAlgorithmSupported($headerArray['alg']);
        Validation::checkSignatureMissing($signature);
        
        Validation::checkClaimType('nbf', 'integer', $payloadArray);
        Validation::checkClaimType('exp', 'integer', $payloadArray);
        Validation::checkClaimType('iat', 'integer', $payloadArray);
        
        Validation::checkClaimType('iss', 'string', $payloadArray);
        Validation::checkClaimType('sub', 'string', $payloadArray);
        Validation::checkClaimType('aud', 'string', $payloadArray);
        Validation::checkClaimType('jti', 'string', $payloadArray);
        
        $this->token = $token;
        $this->payload = $payload;
        $this->header = $header;
        $this->signature = $signature;
    }

    /**
     * Gets message part of the token.
     * 
     * @return string
     */
    public function getMessage(): string
    {
        return sprintf('%s.%s', $this->getHeader(), $this->getPayload());
    }

    /**
     * Gets payload part of the token.
     * 
     * @return string
     */
    public function getPayload(): string
    {
        return $this->payload;
    }

    /**
     * Gets header part of the token.
     * 
     * @return string
     */
    public function getHeader(): string
    {
        return $this->header;
    }

    /**
     * Get signature part of the token.
     * 
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * Performs auto decoding.
     * 
     * @return TokenDecoded
     */
    public function decode(): TokenDecoded
    {
        return JWT::decode($this);
    }

    /**
     * Performs auto validation using given key.
     * 
     * @param string        $key        Key
     * @param string|null   $algorithm  Force algorithm to signature verification (recommended)
     * @param int|null      $leeway     Optional leeway
     * 
     * @return bool
     */
    public function validate(string $key, string $algorithm, ?int $leeway = null): bool
    {
        return JWT::validate($this, $key, $algorithm, $leeway);
    }

    /**
     * Returns string representation of token.
     * 
     * @return string
     */
    public function toString(): string
    {
        return $this->token;
    }
}
