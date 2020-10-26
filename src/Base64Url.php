<?php

namespace Nowakowskir\JWT;

/**
 * Base64 url encode and decode implementation.
 *
 * @author   Radosław Nowakowski <nowakowski.r@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/nowakowskir/php-jwt
 */
class Base64Url
{

    public static function encode($data) : string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode($data) : string
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
