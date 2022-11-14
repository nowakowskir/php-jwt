<?php

namespace Nowakowskir\JWT;

use DateTime;
use Nowakowskir\JWT\Exceptions\InvalidClaimTypeException;
use Nowakowskir\JWT\Exceptions\InvalidStructureException;
use Nowakowskir\JWT\Exceptions\TokenExpiredException;
use Nowakowskir\JWT\Exceptions\TokenInactiveException;
use Nowakowskir\JWT\Exceptions\UndefinedAlgorithmException;
use Nowakowskir\JWT\Exceptions\InsecureTokenException;
use Nowakowskir\JWT\Exceptions\UnsupportedAlgorithmException;
use Nowakowskir\JWT\Exceptions\UnsupportedTokenTypeException;

/**
 * This class contains methods used for validating JWT tokens.
 *
 * @author   Radosław Nowakowski <nowakowski.r@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/nowakowskir/php-jwt
 */
class Validation
{

    /**
     * Checks if expiration date has been reached.
     * 
     * @param int       $exp        Timestamp of expiration date
     * @param int|null  $leeway     Some optional period to avoid clock synchronization issues
     * 
     * @throws TokenExpiredException
     */
    public static function checkExpirationDate(int $exp, ?int $leeway = null): void
    {
        $time = time() - ($leeway ? $leeway : 0);
        
        if ($time >= $exp) {
            throw new TokenExpiredException('Token is not valid since: ' . date(DateTime::ISO8601, $exp));
        }    
    }
    
    /**
     * Checks if not before date has been reached.
     * 
     * @param int       $nbf        Timestamp of activation (not before) date
     * @param int|null  $leeway     Some optional period to avoid clock synchronization issues
     * 
     * @throws TokenInactiveException
     */
    public static function checkNotBeforeDate(int $nbf, ?int $leeway = null): void
    {
        $time = time() + ($leeway ?? 0);

        if ($time < $nbf) {
            throw new TokenInactiveException('Token is not valid before: ' . date(DateTime::ISO8601, $nbf));
        }
    }
    
    /**
     * Checks token structure.
     * 
     * @param string  $token Token
     * 
     * @throws InvalidStructureException
     */
    public static function checkTokenStructure(string $token): void
    {
        $elements = explode('.', $token);

        if (count($elements) !== 3) {
            throw new InvalidStructureException('Wrong number of segments');
        }

        list($header, $payload, $signature) = $elements;

        if (null === json_decode(Base64Url::decode($header))) {
            throw new InvalidStructureException('Invalid header');
        }
        if (null === json_decode(Base64Url::decode($payload))) {
            throw new InvalidStructureException('Invalid payload');
        }
        if (false === Base64Url::decode($signature)) {
            throw new InvalidStructureException('Invalid signature');
        }
    }
    
    public static function checkAlgorithmDefined(array $header)
    {    
        if (! array_key_exists('alg', $header)) {
            throw new UndefinedAlgorithmException('Missing algorithm in token header');
        }       
    }
    
    /**
     * Checks if algorithm has been provided and is supported.
     * 
     * @param string $algorithm
     * 
     * @throws InsecureTokenException
     * @throws UnsupportedAlgorithmException
     */
    public static function checkAlgorithmSupported(string $algorithm)
    {
        if (strtolower($algorithm) === 'none') {
            throw new InsecureTokenException('Unsecure token are not supported: none algorithm provided');
        }
        
        if (! array_key_exists($algorithm, JWT::ALGORITHMS)) {
            throw new UnsupportedAlgorithmException('Invalid algorithm');
        }
    }
    
    /**
     * 
     * @param string $token
     * @return void
     * @throws InsecureTokenException
     */
    public static function checkSignatureMissing(string $signature): void
    {
        if (strlen($signature) === 0) {
            throw new InsecureTokenException('Unsecure token are not supported: signature is missing');
        }    
    }
    
    /**
     * Checks if given key exists in the payload and if so, checks if it's of integer type.
     * 
     * @param string    $claim       Claim name
     * @param array     $payload     Payload array
     * 
     * @throws InvalidClaimTypeException
     */
    public static function checkClaimType(string $claim, string $type, array $payload): void
    {
        switch ($type) {
            case 'integer':
                if (array_key_exists($claim, $payload) && ! is_int($payload[$claim])) {
                    throw new InvalidClaimTypeException(sprintf('Invalid %s claim - %s value required', $claim, $type));
                }
                break;
            case 'string':
            default:
                if (array_key_exists($claim, $payload) && ! is_string($payload[$claim])) {
                    throw new InvalidClaimTypeException(sprintf('Invalid %s claim - %s value required', $claim, $type));
                }
                break;
        }
    }
}
