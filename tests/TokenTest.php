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

/**
 * This class contains set of JWT tests.
 *
 * @author   Radosław Nowakowski <nowakowski.r@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/nowakowskir/php-jwt
 */
class TokenEncodedTest extends TokenBaseTest
{
    /**
     * Checks if tampering token and successful validation is possible when knowing public key and algorithm is not forced during validation.
     * 
     * If token is encoded using RSA algorithm and public key is known to an attacker
     * and validation doesn't enforce specific algorithm to be used
     * it is possible to tamper a token switching its algorithm to HMAC, signing it with public key
     * so the token will be also validated using public key, thus will be successfully validated.
     */
    public function test_bypassing_possible_with_no_algorithm_forcing() : void
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
    
    /**
     * Checks if tampering token and successful validation is not possible when algorithm is forced during validation.
     * 
     * This should result in unsuccessful validation as opposite to test_bypassing_possible_with_no_algorithm_forcing test.
     */
    public function test_bypassing_not_possible_with_algorithm_forcing() : void
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
    
    /**
     * Checks if it's not possible to create encoded token with null value.
     * 
     * This should result with EmptyTokenException.
     */
    public function test_building_encoded_token_with_null() : void
    {
        $this->expectException(EmptyTokenException::class);
        $tokenEncoded = new TokenEncoded(null);
    }
    
    /**
     * Checks if it's not possible to create encoded token with empty string value.
     * 
     * This should result with EmptyTokenException.
     */
    public function test_building_encoded_token_with_empty_string() : void
    {
        $this->expectException(EmptyTokenException::class);
        $tokenEncoded = new TokenEncoded('');
    }
        
    /**
     * Checks if it's not possible to create encoded token with string of invalid structure.
     * 
     * This should result with InvalidStructureException.
     */
    public function test_building_encoded_token_with_invalid_structure() : void
    {
        $this->expectException(InvalidStructureException::class);
        $tokenEncoded = new TokenEncoded('aaa.bbb.ccc');
    }
        
    /**
     * Checks if it's not possible to create encoded token which has none algorithm defined in its header.
     * 
     * This should result with UnsecureTokenException.
     */
    public function test_building_encoded_token_with_none_algorithm() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => 'none']));
        $payload = Base64Url::encode(json_encode([]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(UnsecureTokenException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
            
    /**
     * Checks if it's not possible to create encoded token which has no algorithm defined in its header.
     * 
     * This should result with UndefinedAlgorithmException.
     */
    public function test_building_encoded_token_with_missing_algorithm() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT']));
        $payload = Base64Url::encode(json_encode([]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        
        $this->expectException(UndefinedAlgorithmException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
        
    /**
     * Checks if it's not possible to create encoded token which has empty signature.
     * 
     * This should result with UnsecureTokenException.
     */
    public function test_building_encoded_token_with_empty_signature() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode([]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.', $header, $payload);
        
        $this->expectException(UnsecureTokenException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
            
    /**
     * Checks if it's not possible to create encoded token which has no JWT typ defined in its header.
     * 
     * This should result with UnsupportedTokenTypeException.
     */    
    public function test_building_encoded_token_with_unsupported_token_type() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'XYZ']));
        $payload = Base64Url::encode(json_encode([]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        
        $this->expectException(UnsupportedTokenTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
            
    /**
     * Checks if it's not possible to create encoded token with invalid exp value.
     * 
     * exp must be integer number and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */   
    public function test_building_encoded_token_with_invalid_exp_claim_type() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['exp' => 'string']));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
            
    /**
     * Checks if it's not possible to create encoded token with invalid nbf value.
     * 
     * nbf must be integer number and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */           
    public function test_building_encoded_token_with_invalid_nbf_claim_type() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['nbf' => 'string']));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
            
    /**
     * Checks if it's not possible to create encoded token with invalid iat value.
     * 
     * iat must be integer number and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */                
    public function test_building_encoded_token_with_invalid_iat_claim_type() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['iat' => 'string']));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
    
    /**
     * Checks if it's not possible to create encoded token with invalid iss value.
     * 
     * iss must be string and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */                
    public function test_building_encoded_token_with_invalid_iss_claim_type() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['iss' => 1]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
    
    /**
     * Checks if it's not possible to create encoded token with invalid aud value.
     * 
     * aud must be string and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */                
    public function test_building_encoded_token_with_invalid_aud_claim_type() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['aud' => 1]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
    
    /**
     * Checks if it's not possible to create encoded token with invalid jti value.
     * 
     * jti must be string and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */                
    public function test_building_encoded_token_with_invalid_jti_claim_type() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['jti' => 1]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }

    /**
     * Checks if it's not possible to create encoded token with invalid sub value.
     * 
     * sub must be string and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */                
    public function test_building_encoded_token_with_invalid_sub_claim_type() : void
    {
        $header = Base64Url::encode(json_encode(['typ' => 'JWT', 'alg' => JWT::ALGORITHM_HS256]));
        $payload = Base64Url::encode(json_encode(['sub' => 1]));
        $signature = Base64Url::encode('signature');
        
        $token = sprintf('%s.%s.%s', $header, $payload, $signature);
        $key = ']V@IaC1%fU,DrVI';
        
        $this->expectException(InvalidClaimTypeException::class);
        $tokenEncoded = new TokenEncoded($token);
    }
    
    /**
     * Checks if algorithm passed to encoding method takes priority over algorithm defined in token's header.
     */
    public function test_encoding_with_algorithm_force() : void
    {
        $privateKey = file_get_contents('./tests/keys/private.key');
        
        $tokenDecoded = new TokenDecoded(['alg' => JWT::ALGORITHM_HS256], []);
        $tokenEncoded = $tokenDecoded->encode($privateKey, JWT::ALGORITHM_RS256);
        $tokenString = $tokenEncoded->__toString();
        
        $tokenEncoded = new TokenEncoded($tokenString);
        $header = $tokenEncoded->decode()->getHeader();
        $this->assertEquals(JWT::ALGORITHM_RS256, $header['alg']);
    }

    /**
     * Checks if it's not possible to encode decoded token when provided key doesn't comply with standards of selected algorithm.
     * 
     * This should result with SigningFailedException.
     */   
    public function test_encoding_with_incorrect_key_format_for_given_algorithm() : void
    {
        $this->expectException(SigningFailedException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $exception = false;

        $tokenDecoded = new TokenDecoded(['alg' => JWT::ALGORITHM_RS256], []);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
        
    /**
     * Checks if it's not possible to encode decoded token with no algorithm defined in its header.
     * 
     * This should result with UnsecureTokenException.
     */
    public function test_encoding_with_none_algorithm() : void
    {
        $this->expectException(UnsecureTokenException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded(['alg' => 'none'], []);
        $tokenEncoded = $tokenDecoded->encode($key);        
    }
        
    /**
     * Checks if it's not possible to encode decoded token with unsupported algorithm defined in its header.
     * 
     * This should result with UnsupportedAlgorithmException.
     */
    public function test_encoding_with_unsupported_algorithm() : void
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded(['alg' => 'XYZ'], []);
        $tokenEncoded = $tokenDecoded->encode($key);       
    }
        
    /**
     * Checks if it's not possible to encode decoded token with invalid exp value.

     * exp must be integer and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */
    public function test_encoding_with_wrong_exp_claim_type() : void
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['exp' => 'string']);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
        
    /**
     * Checks if it's not possible to encode decoded token with invalid nbf value.
     * 
     * nbf must be integer and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */        
    public function test_encoding_with_wrong_nbf_claim_type() : void
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['nbf' => 'string']);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
        
    /**
     * Checks if it's not possible to encode decoded token with invalid iat value.
     * 
     * iat must be integer and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */          
    public function test_encoding_with_wrong_iat_claim_type() : void
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['iat' => 'string']);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
        
    /**
     * Checks if it's not possible to encode decoded token with invalid iss value.
     * 
     * iss must be string and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */
    public function test_encoding_with_wrong_iss_claim_type() : void
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['iss' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
        
    /**
     * Checks if it's not possible to encode decoded token with invalid sub value.
     * 
     * sub must be string and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */
    public function test_encoding_with_wrong_sub_claim_type() : void
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['sub' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
        
    /**
     * Checks if it's not possible to encode decoded token with invalid aud value.
     * 
     * aud must be string and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */
    public function test_encoding_with_wrong_aud_claim_type() : void
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['aud' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
        
    /**
     * Checks if it's not possible to encode decoded token with invalid jti value.
     * 
     * jti must be string and other values should not be accepted.
     * 
     * This should result with InvalidClaimTypeException.
     */
    public function test_encoding_with_wrong_jti_claim_type() : void
    {
        $this->expectException(InvalidClaimTypeException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['jti' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
    }
        
    /**
     * Checks if it's possible to encode decoded token when header was set through setter method instead of constructor.
     */
    public function test_encoding_decoding_with_indirect_header() : void
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
        
    /**
     * Checks if it's possible to encode decoded token when payload was set through setter method instead of constructor.
     */    
    public function test_encoding_decoding_with_indirect_payload() : void
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded();
        $tokenDecoded->setPayload(['success' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $payload = $tokenEncoded->decode()->getPayload();
        $this->assertTrue(array_key_exists('success', $payload));
        $this->assertEquals(1, $payload['success']);
    }    
            
    /**
     * Checks if it's possible to encode decoded token when alg was not defined in token's header.
     * 
     * Default algorithm should be set automatically.
     */    
    public function test_encoding_decoding_with_auto_appending_header_alg() : void
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], []);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $header = $tokenEncoded->decode()->getHeader();
        $this->assertTrue(array_key_exists('alg', $header));
        $this->assertEquals(JWT::DEFAULT_ALGORITHM, $header['alg']); 
    }
            
    /**
     * Checks if algorithm defined in token's header won't be overridden by default algorithm.
     * 
     * Initial algorithm defined in token's header should be retained.
     */      
    public function test_encoding_decoding_with_retaining_custom_header_alg() : void
    {
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
            
    /**
     * Checks if it's possible to encode decoded token when typ was not defined in token's header.
     * 
     * Default JWT typ should be set automatically.
     */      
    public function test_encoding_decoding_with_auto_appending_header_typ() : void
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], []);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $header = $tokenEncoded->decode()->getHeader();
        $this->assertTrue(array_key_exists('typ', $header));
        $this->assertEquals('JWT', $header['typ']); 
    }
    
    /**
     * Checks basic decoding payload functionality.
     */
    public function test_decoding_payload() : void
    {
        $key = ']V@IaC1%fU,DrVI';
        
        $tokenDecoded = new TokenDecoded([], ['success' => 1]);
        $tokenEncoded = $tokenDecoded->encode($key);
        
        $payload = $tokenEncoded->decode()->getPayload();
        $this->assertTrue(array_key_exists('success', $payload));
        $this->assertEquals(1, $payload['success']);
    }
    
    /**
     * Checks successful encoding, decoding and validating flow for HS256.
     */
    public function test_validation_integrity_hs256() : void
    {
        $this->token_integrity(JWT::ALGORITHM_HS256, ']V@IaC1%fU,DrVI');
    }
    
    /**
     * Checks unsuccessful encoding, decoding and validating flow for HS256.
     */
    public function test_validation_integrity_violation_hs256() : void
    {
        $this->token_integrity_violation(JWT::ALGORITHM_HS256, ']V@IaC1%fU,DrVI', 'ErC0gfQ0qlkf6WQ');
    }
    
    /**
     * Checks successful encoding, decoding and validating flow for HS384.
     */       
    public function test_validation_integrity_hs384() : void
    {
        $this->token_integrity(JWT::ALGORITHM_HS384, ']V@IaC1%fU,DrVI');
    }
    
    /**
     * Checks unsuccessful encoding, decoding and validating flow for HS384.
     */
    public function test_validation_integrity_violation_hs384() : void
    {
        $this->token_integrity_violation(JWT::ALGORITHM_HS384, ']V@IaC1%fU,DrVI', 'ErC0gfQ0qlkf6WQ');
    }          
    
    /**
     * Checks successful encoding, decoding and validating flow for HS512.
     */ 
    public function test_validation_integrity_hs512() : void
    {
        $this->token_integrity(JWT::ALGORITHM_HS512, ']V@IaC1%fU,DrVI');
    }
    
    /**
     * Checks unsuccessful encoding, decoding and validating flow for HS512.
     */
    public function test_validation_integrity_violation_hs512() : void
    {
        $this->token_integrity_violation(JWT::ALGORITHM_HS512, ']V@IaC1%fU,DrVI', 'ErC0gfQ0qlkf6WQ');
    }
    
    /**
     * Checks successful encoding, decoding and validating flow for RS256.
     */ 
    public function test_validation_integrity_rs256() : void
    {
        $this->token_integrity(JWT::ALGORITHM_RS256, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public.pub'));
    }
    
    /**
     * Checks unsuccessful encoding, decoding and validating flow for RS256.
     */
    public function test_validation_integrity_violation_rs256() : void
    {
        $this->token_integrity_violation(JWT::ALGORITHM_RS256, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public_invalid.pub'));
    }
    
    /**
     * Checks successful encoding, decoding and validating flow for RS384.
     */ 
    public function test_validation_integrity_rs384() : void
    {
        $this->token_integrity(JWT::ALGORITHM_RS384, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public.pub'));
    }
    
    /**
     * Checks unsuccessful encoding, decoding and validating flow for RS384.
     */
    public function test_validation_integrity_violation_rs384() : void
    {
        $this->token_integrity_violation(JWT::ALGORITHM_RS384, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public_invalid.pub'));
    }
    
    /**
     * Checks successful encoding, decoding and validating flow for RS512.
     */   
    public function test_validation_integrity_rs512() : void
    {
        $this->token_integrity(JWT::ALGORITHM_RS512, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public.pub'));
    }
    
    /**
     * Checks unsuccessful encoding, decoding and validating flow for RS512.
     */
    public function test_validation_integrity_violation_rs512() : void
    {
        $this->token_integrity_violation(JWT::ALGORITHM_RS512, file_get_contents('./tests/keys/private.key'), file_get_contents('./tests/keys/public_invalid.pub'));
    }

    /**
     * Checks if validation fails for token with unsupported algorithm.
     * 
     * This should result with UnsupportedAlgorithmException.
     */
    public function test_validating_with_unsupported_algorithm() : void
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

    /**
     * Checks if validation succeeds for token with valid exp.
     */
    public function test_validation_expiration_date_valid() : void
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
    
    /**
     * Checks if validation fails for token with invalid exp.
     * 
     * This should result with TokenExpiredException.
     */
    public function test_validation_with_expiration_date_invalid() : void
    {
        $this->expectException(TokenExpiredException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() - 100;
        
        $tokenDecoded = new TokenDecoded([], ['exp' => $timestamp]);
        $tokenEncoded = $tokenDecoded->encode($key);
    
        $tokenEncoded->validate($key);
    }

    /**
     * Checks if validation succeeds for token with valid exp.
     */
    public function test_validation_with_expiration_date_invalid_leeway_valid() : void
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
        
    /**
     * Checks if validation fails for token with invalid exp and not compensated by leeway.
     * 
     * This should result with TokenExpiredException.
     */
    public function test_validation_with_expiration_date_invalid_leeway_invalid() : void
    {
        $this->expectException(TokenExpiredException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() - 100;

        $tokenDecoded = new TokenDecoded([], ['exp' => $timestamp]);
        $tokenEncoded = $tokenDecoded->encode($key);

        $tokenEncoded->validate($key, null, 100);
    }
    
    /**
     * Checks if validation succeeds for token with valid nbf.
     */
    public function test_validation_with_not_before_date_valid() : void
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
    
    /**
     * Checks if validation fails for token with invalid nbf.
     * 
     * This should result with TokenInactiveException.
     */
    public function test_validation_with_not_before_date_invalid() : void
    {
        $this->expectException(TokenInactiveException::class);
        
        $key = ']V@IaC1%fU,DrVI';
        
        $timestamp = time() + 100;
        
        $tokenDecoded = new TokenDecoded([], ['nbf' => $timestamp]);
        $tokenEncoded = $tokenDecoded->encode($key);
    
        $tokenEncoded->validate($key);
    }

    /**
     * Checks if validation succeeds for token with invalid nbf but compensated by leeway.
     */
    public function test_validation_with_not_before_date_invalid_leeway_valid() : void
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
    
    /**
     * Checks if validation fails for token with invalid nbf and not compensated by leeway.
     * 
     * This should result with TokenInactiveException.
     */
    public function test_validation_with_not_before_date_invalid_leeway_invalid() : void
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
