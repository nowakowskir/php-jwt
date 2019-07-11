<?php
namespace Nowakowskir\JWT;

use \DateTime;
use Nowakowskir\JWT\Exceptions\TokenExpiredException;
use Nowakowskir\JWT\Exceptions\TokenInactiveException;
use Nowakowskir\JWT\Exceptions\InvalidClaimTypeException;
use Nowakowskir\JWT\Exceptions\UndefinedAlgorithmException;
use Nowakowskir\JWT\Exceptions\InvalidStructureException;
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
        $time = time() + ($leeway ? $leeway : 0);
        if ($time < $nbf) {
            throw new TokenInactiveException('Token is not valid before: ' . date(DateTime::ISO8601, $nbf));
        }
    }
    
    /**
     * Checks if algorithm has been defined in token's header.
     * 
     * @param array   $header
     * 
     * @throws UnexpectedValueException
     */
    public static function checkAlgorithm(array $header): void
    {
        if (! array_key_exists('alg', $header)) {
            throw new UndefinedAlgorithmException('Missing algorithm in token header');
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

        if (null === json_decode(base64_decode($header))) {
            throw new InvalidStructureException('Invalid header');
        }
        if (null === json_decode(base64_decode($payload))) {
            throw new InvalidStructureException('Invalid payload');
        }
        if (false === base64_decode($signature)) {
            throw new InvalidStructureException('Invalid signature');
        }
    }
    
    /**
     * Checks if given key exists in the header and if so, checks if it's of integer type.
     * 
     * @param string    $claim      Claim name
     * @param array     $header     Header array
     * 
     * @throws InvalidClaimTypeException
     */
    public static function checkClaimType(string $claim, string $type, array $header): void
    {
        switch ($type) {
            case 'integer':
            default:
                if (array_key_exists($claim, $header) && ! is_int($header[$claim])) {
                    throw new InvalidClaimTypeException(sprintf('Invalid %s claim - %s value required', $claim, $type));
                }
                break;
        }
    }
    
    /**
     * Checks if token is of JWT type.
     * 
     * @param array $header Header array
     * 
     * @throws UnsupportedTokenTypeException
     */
    public static function checkTokenType(array $header): void
    {
        if (! array_key_exists('typ', $header) || $header['typ'] !== 'JWT') {
            throw new UnsupportedTokenTypeException('Unsupported token type');
        }
    }

}
