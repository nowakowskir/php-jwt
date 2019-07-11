<?php
namespace Nowakowskir\JWT;

use \Exception;
use Nowakowskir\JWT\Validation;
use Nowakowskir\JWT\Exceptions\SigningFailedException;
use Nowakowskir\JWT\Exceptions\IntegrityViolationException;
use Nowakowskir\JWT\Exceptions\UnsupportedAlgorithmException;

/**
 * This class contains basic set of methods for handling JSON Web Tokens (JWT).
 *
 * @author   Radosław Nowakowski <nowakowski.r@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/nowakowskir/php-jwt
 */
class JWT
{

    /**
     * List of available algorithms keys.
     */
    const ALGORITHM_HS256 = 'HS256';
    const ALGORITHM_HS384 = 'HS384';
    const ALGORITHM_HS512 = 'HS512';
    const ALGORITHM_RS256 = 'RS256';
    const ALGORITHM_RS384 = 'RS384';
    const ALGORITHM_RS512 = 'RS512';
    
    /**
     * Default algorithm key that will be used in case no algorithm was provided in token's header nor as parameter to encode method.
     */
    const DEFAULT_ALGORITHM = self::ALGORITHM_HS256;
    
    /**
     * Mapping of available algorithm keys with their types and target algorithms.
     */
    const ALGORITHMS = [
        self::ALGORITHM_HS256 => ['hash_hmac', 'SHA256'],
        self::ALGORITHM_HS384 => ['hash_hmac', 'SHA384'],
        self::ALGORITHM_HS512 => ['hash_hmac', 'SHA512'],
        self::ALGORITHM_RS256 => ['openssl', 'SHA256'],
        self::ALGORITHM_RS384 => ['openssl', 'SHA384'],
        self::ALGORITHM_RS512 => ['openssl', 'SHA512'],
    ];

    /**
     * Decodes encoded token.
     * 
     * @param TokenEncoded  $tokenEncoded   Encoded token
     * 
     * @return TokenDecoded
     */
    public static function decode(TokenEncoded $tokenEncoded): TokenDecoded
    {
        return new TokenDecoded(json_decode(base64_decode($tokenEncoded->getHeader()), true), json_decode(base64_decode($tokenEncoded->getPayload()), true));
    }

    /**
     * Encodes decoded token.
     * 
     * @param TokenDecoded  $tokenDecoded   Decoded token
     * @param string        $key            Key used to sign the token
     * @param string|null   $algorithm      Algorithm to use if token's header doesn't contain algorithm definition
     * 
     * @return TokenEncoded
     */
    public static function encode(TokenDecoded $tokenDecoded, string $key, ?string $algorithm = null): TokenEncoded
    {
        $header = array_merge($tokenDecoded->getHeader(), [
            'typ' => array_key_exists('typ', $tokenDecoded->getHeader()) ? $tokenDecoded->getHeader()['typ'] : 'JWT',
            'alg' => array_key_exists('alg', $tokenDecoded->getHeader()) ? $tokenDecoded->getHeader()['alg'] : ($algorithm ? $algorithm : self::DEFAULT_ALGORITHM),
        ]);

        $elements = [];
        $elements[] = base64_encode(json_encode($header));
        $elements[] = base64_encode(json_encode($tokenDecoded->getPayload()));

        $signature = self::sign(implode('.', $elements), $key, $header['alg']);
        $elements[] = base64_encode($signature);

        return new TokenEncoded(implode('.', $elements));
    }

    
    /**
     * Generates signature for given message.
     * 
     * @param string $message   Message to sign, which is base64 encoded values of header and payload separated by dot
     * @param string $key       Key used to sign the token
     * @param string $algorithm Algorithm to use for signing the token
     * 
     * @return string
     * 
     * @throws SigningFailedException
     * @throws SigningFailedException
     */
    protected static function sign(string $message, string $key, string $algorithm): string
    {
        list($function, $type) = self::getAlgorithmData($algorithm);

        switch ($function) {
            case 'hash_hmac':
                try {
                    $signature = hash_hmac($type, $message, $key, true);
                } catch (Exception $e) {
                    throw new SigningFailedException(sprintf('Signing failed: %s', $e->getMessage()));
                }
                if ($signature === false) {
                    throw new SigningFailedException('Signing failed');
                }
                return $signature;
                break;
            case 'openssl':
                $signature = '';
                
                try {
                    $sign = openssl_sign($message, $signature, $key, $type);
                } catch (Exception $e) {
                    throw new SigningFailedException(sprintf('Signing failed: %s', $e->getMessage()));
                }
                
                if (! $sign) {
                    throw new SigningFailedException('Signing failed');
                }
                
                return $signature;
                break;
            default:
                throw new UnsupportedAlgorithmException('Invalid function');
                break;
        }
    }

    /**
     * Validates token's using provided key.
     * 
     * This method should be used to check if given token is valid.
     * 
     * Following things should be verified:
     * - if token contains algorithm defined in its header
     * - if token integrity is met using provided key
     * - if token contains expiration date (exp) in its header - current time against this date
     * - if token contains not before date (nbf) in its header - current time against this date
     * - if token contains issued at date (iat) in its header - current time against this date
     * 
     * @param TokenEncoded  $tokenEncoded   Encoded token
     * @param string        $key            Key used to signature verification
     * @param int|null      $leeway         Some optional period to avoid clock synchronization issues
     * 
     * @return boolean
     * 
     * @throws IntegrityViolationException
     * @throws UnsupportedAlgorithmException
     */
    public static function validate(TokenEncoded $tokenEncoded, string $key, ?int $leeway = null): void
    {
        $tokenDecoded = self::decode($tokenEncoded);

        $signature = base64_decode($tokenEncoded->getSignature());
        $header = $tokenDecoded->getHeader();

        list($function, $type) = self::getAlgorithmData($header['alg']);

        switch ($function) {
            case 'hash_hmac':
                if (hash_equals($signature, hash_hmac($type, $tokenEncoded->getMessage(), $key, true)) !== true) {
                    throw new IntegrityViolationException('Invalid signature');
                }
                break;
            case 'openssl':
                if (openssl_verify($tokenEncoded->getMessage(), $signature, $key, $type) !== 1) {
                    throw new IntegrityViolationException('Invalid signature');
                }
                break;
            default:
                throw new UnsupportedAlgorithmException('Unsupported algorithm type');
                break;
        }
           
        if (array_key_exists('exp', $header)) {
            Validation::checkExpirationDate($header['exp'], $leeway);
        }
        
        if (array_key_exists('nbf', $header)) {
            Validation::checkNotBeforeDate($header['nbf'], $leeway);
        }
        
        if (array_key_exists('iat', $header)) {
            Validation::checkNotBeforeDate($header['iat'], $leeway);
        }
    }
    
    /**
     * Transforms algorithm key into array containing its type and target algorithm.
     * 
     * @param string    $algorithm     Algorithm key
     * 
     * @return array
     * 
     * @throws UnsupportedAlgorithmException
     */
    public static function getAlgorithmData(string $algorithm): array
    {
        if (! array_key_exists($algorithm, self::ALGORITHMS)) {
            throw new UnsupportedAlgorithmException('Invalid algorithm');
        }

        return self::ALGORITHMS[$algorithm];
    }

}
