<?php

namespace Nowakowskir\JWT\Tests;

use \Exception;
use PHPUnit\Framework\TestCase;
use Nowakowskir\JWT\Exceptions\IntegrityViolationException;
use Nowakowskir\JWT\TokenDecoded;
use Nowakowskir\JWT\TokenEncoded;

class TokenBaseTest extends TestCase
{
    
    public function token_integrity($algorithm, $privateKey, $publicKey = null)
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
    
    public function token_integrity_violation($algorithm, $privateKey, $publicKey = null)
    {
        $this->expectException(IntegrityViolationException::class);
        $tokenDecoded = new TokenDecoded(['alg' => $algorithm], ['success' => 1]);
        
        $publicKey = $publicKey ?? $privateKey;
        
        $token = $tokenDecoded->encode($privateKey)->__toString();
        
        $tokenEncoded = new TokenEncoded($token);
        $tokenEncoded->validate($publicKey);
    }
}
