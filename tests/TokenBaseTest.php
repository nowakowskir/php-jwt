<?php

namespace Tests;

use Exception;
use Nowakowskir\JWT\Exceptions\IntegrityViolationException;
use Nowakowskir\JWT\TokenDecoded;
use Nowakowskir\JWT\TokenEncoded;
use PHPUnit\Framework\TestCase;

/**
 * This class contains basic set of methods used for JWT tests.
 *
 * @author   Radosław Nowakowski <nowakowski.r@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/nowakowskir/php-jwt
 */
abstract class TokenBaseTest extends TestCase
{
    
    protected function check_token_integrity($algorithm, $privateKey, $publicKey = null) : void
    {
        $tokenDecoded = new TokenDecoded(['alg' => $algorithm], ['success' => 1]);
        
        $publicKey = $publicKey ?? $privateKey;
        
        $exception = false;
        
        try {
            $token = $tokenDecoded->encode($privateKey, $algorithm)->toString();
        
            $tokenEncoded = new TokenEncoded($token);
            $tokenEncoded->validate($publicKey, $algorithm);
        } catch (Exception $e) {
            $exception = true;
        }
        
        $this->assertFalse($exception);
    }

    protected function check_token_integrity_violation($algorithm, $privateKey, $publicKey = null) : void
    {
        $this->expectException(IntegrityViolationException::class);
        $tokenDecoded = new TokenDecoded(['alg' => $algorithm], ['success' => 1]);
        
        $publicKey = $publicKey ?? $privateKey;
        
        $token = $tokenDecoded->encode($privateKey, $algorithm)->toString();
        
        $tokenEncoded = new TokenEncoded($token);
        $tokenEncoded->validate($publicKey, $algorithm);
    }
}
