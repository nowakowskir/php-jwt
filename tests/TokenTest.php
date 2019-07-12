<?php

namespace Nowakowskir\JWT\Tests;

use Nowakowskir\JWT\Base64Url;
use Nowakowskir\JWT\TokenDecoded;
use Nowakowskir\JWT\TokenEncoded;
use Nowakowskir\JWT\JWT;
use Nowakowskir\JWT\Exceptions\IntegrityViolationException;
use Nowakowskir\JWT\Exceptions\UnsecureTokenException;
use Nowakowskir\JWT\Exceptions\EmptyTokenException;
use Nowakowskir\JWT\Exceptions\InvalidStructureException;
use Nowakowskir\JWT\Exceptions\UndefinedAlgorithmException;
use Nowakowskir\JWT\Exceptions\UnsupportedAlgorithmException;
use Nowakowskir\JWT\Exceptions\InvalidClaimTypeException;
use Nowakowskir\JWT\Exceptions\UnsupportedTokenTypeException;
use Nowakowskir\JWT\Exceptions\TokenExpiredException;
use Nowakowskir\JWT\Exceptions\TokenInactiveException;
use Nowakowskir\JWT\Exceptions\SigningFailedException;
use Nowakowskir\JWT\Tests\TokenBaseTest;

class TokenEncodedTest extends TokenBaseTest
{
    public function test_hacking_possible_with_no_algorithm_forcing()
    {
        // Issuer part
        $issuerTokenDecoded = new TokenDecoded(['alg' => JWT::ALGORITHM_RS256], []);
        $issuerPrivateKey = file_get_contents('./tests/keys/private.key');
        $issuerTokenEncoded = $issuerTokenDecoded->encode($issuerPrivateKey);
        $issuerTokenString = $issuerTokenEncoded->__toString();
        
        // Attacker part
        $capturedPublicKey = file_get_contents('./tests/keys/public.pub');
        $attackerTokenEncoded = new TokenEncoded($issuerTokenString);
        $attackerTokenDecoded = $attackerTokenEncoded->decode();
        $header = $attackerTokenDecoded->getHeader();
        $header['alg'] = JWT::ALGORITHM_HS256;
        $attackerTokenDecoded->setHeader($header);
        $craftedTokenEncoded = $attackerTokenDecoded->encode($capturedPublicKey);
        $craftedTokenString = $craftedTokenEncoded->__toString();
        
        // Verifier part
        $verifierPublicKey = file_get_contents('./tests/keys/public.pub');
        $verifierTokenEncoded = new TokenEncoded($craftedTokenString);
        
        $exception = false;
        try {
            $verifierTokenEncoded->validate($verifierPublicKey);
        } catch (IntegrityViolationException $ex) {
            $exception = true;
        }
        
        $this->assertFalse($exception);
    }
    
    public function test_hacking_not_possible_with_algorithm_forcing()
    {
        // Issuer part
        $issuerTokenDecoded = new TokenDecoded(['alg' => JWT::ALGORITHM_RS256], []);
        $issuerPrivateKey = file_get_contents('./tests/keys/private.key');
        $issuerTokenEncoded = $issuerTokenDecoded->encode($issuerPrivateKey);
        $issuerTokenString = $issuerTokenEncoded->__toString();
        
        // Attacker part
        $capturedPublicKey = file_get_contents('./tests/keys/public.pub');
        $attackerTokenEncoded = new TokenEncoded($issuerTokenString);
        $attackerTokenDecoded = $attackerTokenEncoded->decode();
        $header = $attackerTokenDecoded->getHeader();
        $header['alg'] = JWT::ALGORITHM_HS256;
        $attackerTokenDecoded->setHeader($header);
        $craftedTokenEncoded = $attackerTokenDecoded->encode($capturedPublicKey);
        $craftedTokenString = $craftedTokenEncoded->__toString();
        
        // Verifier part
        $verifierPublicKey = file_get_contents('./tests/keys/public.pub');
        $verifierTokenEncoded = new TokenEncoded($craftedTokenString);
        
        $exception = false;
        try {
            $verifierTokenEncoded->validate($verifierPublicKey, JWT::ALGORITHM_RS256);
        } catch (IntegrityViolationException $ex) {
            $exception = true;
        }
        
        $this->assertTrue($exception);
    }
    
    public function test_building_encoded_token_with_null()
    {
        $this->expectException(EmptyTokenException::class);
        $tokenEncoded = new TokenEncoded(null);
    }

    public function test_building_encoded_token_with_empty_string()
    {
        $this->expectException(EmptyTokenException::class);
        $tokenEncoded = new TokenEncoded('');
    }
    
    public function test_building_encoded_token_with_invalid_structure()
    {
        $this->expectException(InvalidStructureException::class);
        $tokenEncoded = new TokenEncoded('aaa.bbb.ccc');
    }

    public function test_building_encoded_token_with_none_algorithm()
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => 'none']));
        $payload = Base64Url::encode(json_encode([]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(UnsecureTokenException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
    
    public function test_building_encoded_token_with_missing_algorithm()
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT']));
        $payload = Base64Url::encode(json_encode([]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        
        $this->expectException(UndefinedAlgorithmException::class);
        $tokenEncoded = new TokenEncoded($token);
    }

    public function test_building_encoded_token_with_empty_signature()
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode([]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.', $header, $payload);
        
        $this->expectException(UnsecureTokenException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
        
    public function test_building_encoded_token_with_unsupported_token_type()
    {
        $header = Base64Url::encode(json_encode(['typ' => 'XYZ']));
        $payload = Base64Url::encode(json_encode([]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        
        $this->expectException(UnsupportedTokenTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
    
    public function test_building_encoded_token_with_invalid_exp_claim_type()
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['exp' => 'string']));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
        
    public function test_building_encoded_token_with_invalid_nbf_claim_type()
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['nbf' => 'string']));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
            
    public function test_building_encoded_token_with_invalid_iat_claim_type()
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['iat' => 'string']));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }

    public function test_encoding_with_algorithm_force()
    {
        $privateKey = file_get_contents('./tests/keys/private.key');
        
        $tokenDecoded = new TokenDecoded(['alg' => JWT::ALGORITHM_HS256], []);
        $tokenEncoded = $tokenDecoded->encode($privateKey, JWT::ALGORITHM_RS256);
        $tokenString = $tokenEncoded->__toString();
        
        $tokenEncoded = new TokenEncoded($tokenString);
        $header = $tokenEncoded->decode()->getHeader();
        $this->assertEquals(JWT::ALGORITHM_RS256, $header['alg']);
    }
    
    public function test_encoding_with_incorrect_key_format_for_given_algorithm()
    {
        $this->expectException(SigningFailedException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $exception = false;

        $tokenDecoded = new TokenDecoded(['alg' => JWT::ALGORITHM_RS256], []);
        $tokenEncoded = $tokenDecoded->encode($key);
    }

    public function test_encoding_with_none_algorithm()
    {
        $this->expectException(UnsecureTokenException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded(['alg' => 'none'], []);
        $tokenEncoded = $tokenDecoded->encode($key);        
    }
        
    public function test_encoding_with_unsupported_algorithm()
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded(['alg' => 'XYZ'], []);
        $tokenEncoded = $tokenDecoded->encode($key);       
    }
    
    public function test_encoding_with_wrong_exp_claim_type()
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['exp' => 'string']);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
        
    public function test_encoding_with_wrong_nbf_claim_type()
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['nbf' => 'string']);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
            
    public function test_encoding_with_wrong_iat_claim_type()
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['iat' => 'string']);
        $tokenEncoded = $tokenDecoded->encode($key);
    }

    public function test_encoding_with_wrong_iss_claim_type()
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['iss' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
    }

    public function test_encoding_with_wrong_sub_claim_type()
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['sub' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
    }

    public function test_encoding_with_wrong_aud_claim_type()
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['aud' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
    }

    public function test_encoding_with_wrong_jti_claim_type()
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['jti' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
    
    public function test_encoding_decoding_with_indirect_header()
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time();
        
        $tokenDecoded = new TokenDecoded();
        $tokenDecoded->setHeader(['xyz' => $timestamp]);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $header = $tokenEncoded->decode()->getHeader();
        $this->assertTrue(array_key_exists('xyz', $header));
        $this->assertEquals($timestamp, $header['xyz']);
    }
    
    public function test_encoding_decoding_with_indirect_payload()
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded();
        $tokenDecoded->setPayload(['success' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $payload = $tokenEncoded->decode()->getPayload();
        $this->assertTrue(array_key_exists('success', $payload));
        $this->assertEquals(1, $payload['success']);
    }    
    
    public function test_encoding_decoding_with_auto_appending_header_alg() {
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], []);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $header = $tokenEncoded->decode()->getHeader();
        $this->assertTrue(array_key_exists('alg', $header));
        $this->assertEquals(JWT::DEFAULT_ALGORITHM, $header['alg']); 
    }
    
    public function test_encoding_decoding_with_retaining_custom_header_alg() {
        $key = ']V@IaC1%fU,DrVI';
        
        foreach (JWT::ALGORITHMS as $key => $values) {
            if ($key === JWT::DEFAULT_ALGORITHM) {
                continue;
            }
            $algorithm = $key;
            break;
        }
        
        $tokenDecoded = new TokenDecoded(['alg' => $algorithm], []);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $header = $tokenEncoded->decode()->getHeader();
        $this->assertTrue(array_key_exists('alg', $header));
        $this->assertEquals($algorithm, $header['alg']); 
    }
    
    public function test_encoding_decoding_with_auto_appending_header_typ() {
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], []);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $header = $tokenEncoded->decode()->getHeader();
        $this->assertTrue(array_key_exists('typ', $header));
        $this->assertEquals('JWT', $header['typ']); 
    }
    
    public function test_decoding_payload()
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['success' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $payload = $tokenEncoded->decode()->getPayload();
        $this->assertTrue(array_key_exists('success', $payload));
        $this->assertEquals(1, $payload['success']);
    }
    
    public function test_validation_integrity_hs256()
    {
        $this->token_integrity(JWT::ALGORITHM_HS256, ']V@IaC1%fU,DrVI');
    }
    
    public function test_validation_integrity_violation_hs256()
    {
        $this->token_integrity_violation(JWT::ALGORITHM_HS256, ']V@IaC1%fU,DrVI', 'ErC0gfQ0qlkf6WQ');
    }
            
    public function test_validation_integrity_hs384()
    {
        $this->token_integrity(JWT::ALGORITHM_HS384, ']V@IaC1%fU,DrVI');
    }
    
    public function test_validation_integrity_violation_hs384()
    {
        $this->token_integrity_violation(JWT::ALGORITHM_HS384, ']V@IaC1%fU,DrVI', 'ErC0gfQ0qlkf6WQ');
    }          
    
    public function test_validation_integrity_hs512()
    {
        $this->token_integrity(JWT::ALGORITHM_HS512, ']V@IaC1%fU,DrVI');
    }
    
    public function test_validation_integrity_violation_hs512()
    {
        $this->token_integrity_violation(JWT::ALGORITHM_HS512, ']V@IaC1%fU,DrVI', 'ErC0gfQ0qlkf6WQ');
    }

    public function test_validation_integrity_rs256()
    {
        $this->token_integrity(JWT::ALGORITHM_RS256, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public.pub'));
    }
    
    public function test_validation_integrity_violation_rs256()
    {
        $this->token_integrity_violation(JWT::ALGORITHM_RS256, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public_invalid.pub'));
    }
    
    public function test_validation_integrity_rs384()
    {
        $this->token_integrity(JWT::ALGORITHM_RS384, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public.pub'));
    }
    
    public function test_validation_integrity_violation_rs384()
    {
        $this->token_integrity_violation(JWT::ALGORITHM_RS384, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public_invalid.pub'));
    }
        
    public function test_validation_integrity_rs512()
    {
        $this->token_integrity(JWT::ALGORITHM_RS512, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public.pub'));
    }
    
    public function test_validation_integrity_violation_rs512()
    {
        $this->token_integrity_violation(JWT::ALGORITHM_RS512, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public_invalid.pub'));
    }


    public function test_validating_with_unsupported_algorithm()
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => 'XYZ']));
        $payload = Base64Url::encode(json_encode([]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(UnsupportedAlgorithmException::class);
        $tokenEncoded = new TokenEncoded($token);
        $tokenEncoded->validate($key);
    }

    public function test_validation_expiration_date_valid()
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() + 100;
        
        $exception = false;
        
        try {
            $tokenDecoded = new TokenDecoded([], ['exp' => $timestamp]);
            $tokenEncoded = $tokenDecoded->encode($key);

            $tokenEncoded->validate($key);
        } catch (Exception $e) {
            $exception = true;
        }
        
        $this->assertFalse($exception);
    }
    
    public function test_validation_with_expiration_date_invalid()
    {
        $this->expectException(TokenExpiredException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() - 100;
        
        $tokenDecoded = new TokenDecoded([], ['exp' => $timestamp]);
        $tokenEncoded = $tokenDecoded->encode($key);
    
        $tokenEncoded->validate($key);
    }

    public function test_validation_with_expiration_date_invalid_leeway_valid()
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() - 100;
        
        $exception = false;
        
        try {
            $tokenDecoded = new TokenDecoded([], ['exp' => $timestamp]);
            $tokenEncoded = $tokenDecoded->encode($key);

            $tokenEncoded->validate($key, null, 101);
        } catch (Exception $e) {
            $exception = true;
        }
        
        $this->assertFalse($exception);
    }
    
    public function test_validation_with_expiration_date_invalid_leeway_invalid()
    {
        $this->expectException(TokenExpiredException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() - 100;

        $tokenDecoded = new TokenDecoded([], ['exp' => $timestamp]);
        $tokenEncoded = $tokenDecoded->encode($key);

        $tokenEncoded->validate($key, null, 100);
    }
    
    public function test_validation_with_not_before_date_valid()
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() - 100;
        
        $exception = false;
        
        try {
            $tokenDecoded = new TokenDecoded([], ['nbf' => $timestamp]);
            $tokenEncoded = $tokenDecoded->encode($key);

            $tokenEncoded->validate($key);
        } catch (Exception $e) {
            $exception = true;
        }
        
        $this->assertFalse($exception);
    }

    public function test_validation_with_not_before_date_invalid()
    {
        $this->expectException(TokenInactiveException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() + 100;
        
        $tokenDecoded = new TokenDecoded([], ['nbf' => $timestamp]);
        $tokenEncoded = $tokenDecoded->encode($key);
    
        $tokenEncoded->validate($key);
    }

    public function test_validation_with_not_before_date_invalid_leeway_valid()
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() + 100;
        
        $exception = false;
        
        try {
            $tokenDecoded = new TokenDecoded([], ['nbf' => $timestamp]);
            $tokenEncoded = $tokenDecoded->encode($key);

            $tokenEncoded->validate($key, null, 100);
        } catch (Exception $e) {
            $exception = true;
        }
        
        $this->assertFalse($exception);
    }
    
    public function test_validation_with_not_before_date_invalid_leeway_invalid()
    {
        $this->expectException(TokenInactiveException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() + 100;
        
        $exception = false;

        $tokenDecoded = new TokenDecoded([], ['nbf' => $timestamp]);
        $tokenEncoded = $tokenDecoded->encode($key);

        $tokenEncoded->validate($key, null, 99);
    }
    
}
