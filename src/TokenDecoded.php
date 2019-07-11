<?php
namespace Nowakowskir\JWT;

/**
 * This class is representation of decoded JSON Web Token (JWT).
 *
 * @author   Radosław Nowakowski <nowakowski.r@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/nowakowskir/php-jwt
 */
class TokenDecoded
{

    /**
     * Array containing token's header elements.
     */
    protected $header;
    
    /**
     * Array containing token's payload elements.
     */
    protected $payload;

    /**
     * @param array|null $header
     * @param array|null $payload
     */
    public function __construct(?array $header = [], ?array $payload = [])
    {
        $this->payload = $payload;
        $this->header = $header;
    }

    /**
     * Gets array with token's payload.
     * 
     * @return array
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * Sets array with token's payload.
     * 
     * @param array $payload
     */
    public function setPayload(array $payload): void
    {
        $this->payload = $payload;
    }

    /**
     * Gets array with token's header.
     * 
     * @return array
     */
    public function getHeader(): array
    {
        return $this->header;
    }

    /**
     * Sets array with token's header.
     * 
     * @param array $header
     */
    public function setHeader(array $header): void
    {
        $this->header = $header;
    }

    /**
     * Performs auto encoding.
     * 
     * @param string        $key        Key used to signing token.
     * @param string|null   $algorithm  Optional algorithm to be used when algorithm is not yet defined in token's header.
     * 
     * @return TokenEncoded
     */
    public function encode(string $key, ?string $algorithm = null) : TokenEncoded
    {
        return JWT::encode($this, $key, $algorithm);
    }
}
