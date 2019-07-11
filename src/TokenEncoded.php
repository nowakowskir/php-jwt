<?php
namespace Nowakowskir\JWT;

use Nowakowskir\JWT\JWT;
use Nowakowskir\JWT\Validation;
use Nowakowskir\JWT\Exceptions\EmptyTokenException;

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
     * String representation of encoded token.
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
     * @param string|null $token
     * 
     * @throws EmptyTokenException
     */
    public function __construct(?string $token = null)
    {
        if ($token === null || $token === '') {
            throw new EmptyTokenException('Token not provided');
        }

        Validation::checkTokenStructure($token);
        
        $elements = explode('.', $token);
        list($header, $payload, $signature) = $elements;
        
        $headerArray = json_decode(base64_decode($header), true);
        Validation::checkTokenType($headerArray);
        Validation::checkAlgorithm($headerArray);
        Validation::checkClaimType('nbf', 'integer', $headerArray);
        Validation::checkClaimType('exp', 'integer', $headerArray);
        Validation::checkClaimType('iat', 'integer', $headerArray);
        
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
     * @return \Nowakowskir\JWT\TokenDecoded
     */
    public function decode(): TokenDecoded
    {
        return JWT::decode($this);
    }

    /**
     * Performs auto validation using given key.
     * 
     * @param string $key
     * 
     * @return bool
     */
    public function validate(string $key, int $leeway = null): void
    {
        JWT::validate($this, $key, $leeway);
    }

    /**
     * Returns string representation of token.
     * 
     * @return string
     */
    public function __toString(): string
    {
        return $this->token;
    }
}
