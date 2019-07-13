<?php

namespace Nowakowskir\JWT\Tests;

use \Exception;
use PHPUnit\Framework\TestCase;
use Nowakowskir\JWT\Exceptions\IntegrityViolationException;
use Nowakowskir\JWT\TokenDecoded;
use Nowakowskir\JWT\TokenEncoded;

/**
 * This class contains basic set of methods used for JWT tests.
 *
 * @author   Radosław Nowakowski <nowakowski.r@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/nowakowskir/php-jwt
 */
class TokenBaseTest extends TestCase
{
    
    public function token_integrity($algorithm, $privateKey, $publicKey = null) : void
    {
        $tokenDecoded = new TokenDecoded(['alg' => $algorithm], ['success' => 1]);
        
        $publicKey = $publicKey ?? $privateKey;
        
        $exception = false;
        
        try {
            $token = $tokenDecoded->encode($privateKey)->__toString();
        
            $tokenEncoded = new TokenEncoded($token);
            $tokenEncoded->validate($publicKey);
        } catch (Exception $e) {
            $exception = true;
        }
        
        $this->assertFalse($exception);
    }
    
    public function token_integrity_violation($algorithm, $privateKey, $publicKey = null) : void
    {
        $this->expectException(IntegrityViolationException::class);
        $tokenDecoded = new TokenDecoded(['alg' => $algorithm], ['success' => 1]);
        
        $publicKey = $publicKey ?? $privateKey;
        
        $token = $tokenDecoded->encode($privateKey)->__toString();
        
        $tokenEncoded = new TokenEncoded($token);
        $tokenEncoded->validate($publicKey);
    }
}
