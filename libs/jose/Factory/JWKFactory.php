<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\KeyConverter\ECKey;
use Jose\KeyConverter\KeyConverter;
use Jose\KeyConverter\RSAKey;
use Jose\Object\JKUJWKSet;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWKSets;
use Jose\Object\PublicJWKSet;
use Jose\Object\RotatableJWKSet;
use Jose\Object\StorableJWK;
use Jose\Object\StorableJWKSet;
use Jose\Object\X5UJWKSet;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Curves\NistCurve;
use Mdanter\Ecc\EccFactory;
use Psr\Cache\CacheItemPoolInterface;

final class JWKFactory implements JWKFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public static function createPublicKeySet(JWKSetInterface $jwkset)
    {
        return new PublicJWKSet($jwkset);
    }

    /**
     * {@inheritdoc}
     */
    public static function createKeySets(array $jwksets = [])
    {
        return new JWKSets($jwksets);
    }

    /**
     * {@inheritdoc}
     */
    public static function createStorableKey($filename, array $parameters)
    {
        return new StorableJWK($filename, $parameters);
    }

    /**
     * {@inheritdoc}
     */
    public static function createRotatableKeySet($filename, array $parameters, $nb_keys, $interval = null)
    {
        return new RotatableJWKSet($filename, $parameters, $nb_keys, $interval);
    }

    /**
     * {@inheritdoc}
     */
    public static function createStorableKeySet($filename, array $parameters, $nb_keys)
    {
        return new StorableJWKSet($filename, $parameters, $nb_keys);
    }

    /**
     * {@inheritdoc}
     */
    public static function createKey(array $config)
    {
        Assertion::keyExists($config, 'kty', 'The key "kty" must be set');
        $supported_types = ['RSA' => 'RSA', 'OKP' => 'OKP', 'EC' => 'EC', 'oct' => 'Oct', 'none' => 'None'];
        $kty = $config['kty'];
        Assertion::keyExists($supported_types, $kty, sprintf('The key type "%s" is not supported. Please use one of %s', $kty, json_encode(array_keys($supported_types))));
        $method = sprintf('create%sKey', $supported_types[$kty]);

        return self::$method($config);
    }

    /**
     * {@inheritdoc}
     */
    public static function createRSAKey(array $values)
    {
        $config = array();
        $config['config'] = dirname(__FILE__) . '/../openssl.cnf';

        Assertion::keyExists($values, 'size', 'The key size is not set.');
        $size = $values['size'];
        unset($values['size']);

        Assertion::true(0 === $size % 8, 'Invalid key size.');
        Assertion::greaterOrEqualThan($size, 384, 'Key length is too short. It needs to be at least 384 bits.');

        $key = openssl_pkey_new([
            'private_key_bits' => $size,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ] + $config);
        openssl_pkey_export($key, $out, null, $config);
        $rsa = new RSAKey($out);
        $values = array_merge(
            $values,
            $rsa->toArray()
        );

        //            $privatekey = call_user_func_array(array($this, '_convertPrivateKey'), array_values($this->_parseKey($privatekey, self::PRIVATE_FORMAT_PKCS1)));
        //            $publickey = call_user_func_array(array($this, '_convertPublicKey'), array_values($this->_parseKey($publickey, self::PUBLIC_FORMAT_PKCS1)));

        return new JWK($values);
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @access private
     * @see self::setPrivateKeyFormat()
     * @param string $RSAPrivateKey
     * @return string
     */
    /*function _convertPrivateKey($n, $e, $d, $primes, $exponents, $coefficients)
    {
        $signed = $this->privateKeyFormat != self::PRIVATE_FORMAT_XML;
        $num_primes = count($primes);
        $raw = array(
            'version' => $num_primes == 2 ? chr(0) : chr(1), // two-prime vs. multi
            'modulus' => $n->toBytes($signed),
            'publicExponent' => $e->toBytes($signed),
            'privateExponent' => $d->toBytes($signed),
            'prime1' => $primes[1]->toBytes($signed),
            'prime2' => $primes[2]->toBytes($signed),
            'exponent1' => $exponents[1]->toBytes($signed),
            'exponent2' => $exponents[2]->toBytes($signed),
            'coefficient' => $coefficients[2]->toBytes($signed)
        );

                $components = array();
                foreach ($raw as $name => $value) {
                    $components[$name] = pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($value)), $value);
                }

                $RSAPrivateKey = implode('', $components);

                if ($num_primes > 2) {
                    $OtherPrimeInfos = '';
                    for ($i = 3; $i <= $num_primes; $i++) {
                        // OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
                        //
                        // OtherPrimeInfo ::= SEQUENCE {
                        //     prime             INTEGER,  -- ri
                        //     exponent          INTEGER,  -- di
                        //     coefficient       INTEGER   -- ti
                        // }
                        $OtherPrimeInfo = pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($primes[$i]->toBytes(true))), $primes[$i]->toBytes(true));
                        $OtherPrimeInfo.= pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($exponents[$i]->toBytes(true))), $exponents[$i]->toBytes(true));
                        $OtherPrimeInfo.= pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($coefficients[$i]->toBytes(true))), $coefficients[$i]->toBytes(true));
                        $OtherPrimeInfos.= pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($OtherPrimeInfo)), $OtherPrimeInfo);
                    }
                    $RSAPrivateKey.= pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($OtherPrimeInfos)), $OtherPrimeInfos);
                }

                $RSAPrivateKey = pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($RSAPrivateKey)), $RSAPrivateKey);

                if ($this->privateKeyFormat == self::PRIVATE_FORMAT_PKCS8) {
                    $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
                    $RSAPrivateKey = pack(
                        'Ca*a*Ca*a*',
                        self::ASN1_INTEGER,
                        "\01\00",
                        $rsaOID,
                        4,
                        $this->_encodeLength(strlen($RSAPrivateKey)),
                        $RSAPrivateKey
                    );
                    $RSAPrivateKey = pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($RSAPrivateKey)), $RSAPrivateKey);
                    if (!empty($this->password) || is_string($this->password)) {
                        $salt = Random::string(8);
                        $iterationCount = 2048;

                        $crypto = new DES();
                        $crypto->setPassword($this->password, 'pbkdf1', 'md5', $salt, $iterationCount);
                        $RSAPrivateKey = $crypto->encrypt($RSAPrivateKey);

                        $parameters = pack(
                            'Ca*a*Ca*N',
                            self::ASN1_OCTETSTRING,
                            $this->_encodeLength(strlen($salt)),
                            $salt,
                            self::ASN1_INTEGER,
                            $this->_encodeLength(4),
                            $iterationCount
                        );
                        $pbeWithMD5AndDES_CBC = "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x03";

                        $encryptionAlgorithm = pack(
                            'Ca*a*Ca*a*',
                            self::ASN1_OBJECT,
                            $this->_encodeLength(strlen($pbeWithMD5AndDES_CBC)),
                            $pbeWithMD5AndDES_CBC,
                            self::ASN1_SEQUENCE,
                            $this->_encodeLength(strlen($parameters)),
                            $parameters
                        );

                        $RSAPrivateKey = pack(
                            'Ca*a*Ca*a*',
                            self::ASN1_SEQUENCE,
                            $this->_encodeLength(strlen($encryptionAlgorithm)),
                            $encryptionAlgorithm,
                            self::ASN1_OCTETSTRING,
                            $this->_encodeLength(strlen($RSAPrivateKey)),
                            $RSAPrivateKey
                        );

                        $RSAPrivateKey = pack('Ca*a*', self::ASN1_SEQUENCE, $this->_encodeLength(strlen($RSAPrivateKey)), $RSAPrivateKey);

                        $RSAPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n" .
                            chunk_split(base64_encode($RSAPrivateKey), 64) .
                            '-----END ENCRYPTED PRIVATE KEY-----';
                    } else {
                        $RSAPrivateKey = "-----BEGIN PRIVATE KEY-----\r\n" .
                            chunk_split(base64_encode($RSAPrivateKey), 64) .
                            '-----END PRIVATE KEY-----';
                    }
                    return $RSAPrivateKey;

        }
    }*/

    /**
     * Convert a public key to the appropriate format
     *
     * @access private
     * @see self::setPublicKeyFormat()
     * @param string $RSAPrivateKey
     * @return string
     */
    /*function _convertPublicKey($n, $e)
    {
        $signed = $this->publicKeyFormat != self::PUBLIC_FORMAT_XML;

        $modulus = $n->toBytes($signed);
        $publicExponent = $e->toBytes($signed);


             // eg. self::PUBLIC_FORMAT_PKCS1_RAW or self::PUBLIC_FORMAT_PKCS1
                // from <http://tools.ietf.org/html/rfc3447#appendix-A.1.1>:
                // RSAPublicKey ::= SEQUENCE {
                //     modulus           INTEGER,  -- n
                //     publicExponent    INTEGER   -- e
                // }
                $components = array(
                    'modulus' => pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($modulus)), $modulus),
                    'publicExponent' => pack('Ca*a*', self::ASN1_INTEGER, $this->_encodeLength(strlen($publicExponent)), $publicExponent)
                );

                $RSAPublicKey = pack(
                    'Ca*a*a*',
                    self::ASN1_SEQUENCE,
                    $this->_encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
                    $components['modulus'],
                    $components['publicExponent']
                );

                if ($this->publicKeyFormat == self::PUBLIC_FORMAT_PKCS1_RAW) {
                    $RSAPublicKey = "-----BEGIN RSA PUBLIC KEY-----\r\n" .
                        chunk_split(base64_encode($RSAPublicKey), 64) .
                        '-----END RSA PUBLIC KEY-----';
                } else {
                    // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
                    $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
                    $RSAPublicKey = chr(0) . $RSAPublicKey;
                    $RSAPublicKey = chr(3) . $this->_encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;

                    $RSAPublicKey = pack(
                        'Ca*a*',
                        self::ASN1_SEQUENCE,
                        $this->_encodeLength(strlen($rsaOID . $RSAPublicKey)),
                        $rsaOID . $RSAPublicKey
                    );

                    $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
                        chunk_split(base64_encode($RSAPublicKey), 64) .
                        '-----END PUBLIC KEY-----';
                }

                return $RSAPublicKey;
    }*/

    /**
     * {@inheritdoc}
     */
    public static function createECKey(array $values)
    {
        Assertion::keyExists($values, 'crv', 'The curve is not set.');
        $curve = $values['crv'];
        if (function_exists('openssl_get_curve_names')) {
            $args = [
                'curve_name' => self::getOpensslName($curve),
                'private_key_type' => OPENSSL_KEYTYPE_EC,
            ];
            $key = openssl_pkey_new($args);
            $res = openssl_pkey_export($key, $out);
            Assertion::true($res, 'Unable to create the key');

            $rsa = new ECKey($out);
            $values = array_merge(
                $values,
                $rsa->toArray()
            );

            return new JWK($values);
        } else {
            $curve_name = self::getNistName($curve);
            $generator = CurveFactory::getGeneratorByName($curve_name);
            $private_key = $generator->createPrivateKey();

            $values = array_merge(
                $values,
                [
                    'kty' => 'EC',
                    'crv' => $curve,
                    'x' => self::encodeValue($private_key->getPublicKey()->getPoint()->getX()),
                    'y' => self::encodeValue($private_key->getPublicKey()->getPoint()->getY()),
                    'd' => self::encodeValue($private_key->getSecret()),
                ]
            );
        }

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createOctKey(array $values)
    {
        Assertion::keyExists($values, 'size', 'The key size is not set.');
        $size = $values['size'];
        unset($values['size']);
        Assertion::true(0 === $size % 8, 'Invalid key size.');
        $values = array_merge(
            $values,
            [
                'kty' => 'oct',
                'k' => Base64Url::encode(random_bytes($size / 8)),
            ]
        );

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createOKPKey(array $values)
    {
        Assertion::keyExists($values, 'crv', 'The curve is not set.');
        $curve = $values['crv'];
        switch ($curve) {
            case 'X25519':
                Assertion::true(function_exists('curve25519_public'), sprintf('Unsupported "%s" curve', $curve));
                $d = random_bytes(32);
                $x = curve25519_public($d);

                break;
            case 'Ed25519':
                Assertion::true(function_exists('ed25519_publickey'), sprintf('Unsupported "%s" curve', $curve));
                $d = random_bytes(32);
                $x = ed25519_publickey($d);

                break;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported "%s" curve', $curve));
        }

        $values = array_merge(
            $values,
            [
                'kty' => 'OKP',
                'crv' => $curve,
                'x' => Base64Url::encode($x),
                'd' => Base64Url::encode($d),
            ]
        );

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createNoneKey(array $values)
    {
        $values = array_merge(
            $values,
            [
                'kty' => 'none',
                'alg' => 'none',
                'use' => 'sig',
            ]
        );

        return new JWK($values);
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private static function encodeValue($value)
    {
        $value = gmp_strval($value);

        return Base64Url::encode(self::convertDecToBin($value));
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private static function convertDecToBin($value)
    {
        $adapter = EccFactory::getAdapter();

        return hex2bin($adapter->decHex($value));
    }

    /**
     * @param string $curve
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getOpensslName($curve)
    {
        switch ($curve) {
            case 'P-256':
                return 'prime256v1';
            case 'P-384':
                return 'secp384r1';
            case 'P-521':
                return 'secp521r1';
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve));
        }
    }

    /**
     * @param string $curve
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getNistName($curve)
    {
        switch ($curve) {
            case 'P-256':
                return NistCurve::NAME_P256;
            case 'P-384':
                return NistCurve::NAME_P384;
            case 'P-521':
                return NistCurve::NAME_P521;
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve));
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromValues(array $values)
    {
        if (array_key_exists('keys', $values) && is_array($values['keys'])) {
            return new JWKSet($values);
        }

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromCertificateFile($file, array $additional_values = [])
    {
        $values = KeyConverter::loadKeyFromCertificateFile($file);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromCertificate($certificate, array $additional_values = [])
    {
        $values = KeyConverter::loadKeyFromCertificate($certificate);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromX509Resource($res, array $additional_values = [])
    {
        $values = KeyConverter::loadKeyFromX509Resource($res);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromKeyFile($file, $password = null, array $additional_values = [])
    {
        $values = KeyConverter::loadFromKeyFile($file, $password);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromKey($key, $password = null, array $additional_values = [])
    {
        $values = KeyConverter::loadFromKey($key, $password);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromJKU($jku, $allow_unsecured_connection = false, CacheItemPoolInterface $cache = null, $ttl = 86400, $allow_http_connection = false, array $custom_headers = [])
    {
        return new JKUJWKSet($jku, $cache, $ttl, $allow_unsecured_connection, $allow_http_connection, $custom_headers);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromX5U($x5u, $allow_unsecured_connection = false, CacheItemPoolInterface $cache = null, $ttl = 86400, $allow_http_connection = false, array $custom_headers = [])
    {
        return new X5UJWKSet($x5u, $cache, $ttl, $allow_unsecured_connection, $allow_http_connection, $custom_headers);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromX5C(array $x5c, array $additional_values = [])
    {
        $values = KeyConverter::loadFromX5C($x5c);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromKeySet(JWKSetInterface $jwk_set, $key_index)
    {
        Assertion::integer($key_index);

        return $jwk_set->getKey($key_index);
    }
}
