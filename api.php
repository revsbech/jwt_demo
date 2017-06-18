<?php
require_once('vendor/autoload.php');


use Namshi\JOSE\SimpleJWS;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

class ApiDemo {
    const OpenIdConfig = "https://cognito-identity.amazonaws.com/.well-known/openid-configuration";
    const CognitoIdentityKeyEndpoint = "https://cognito-identity.amazonaws.com/.well-known/jwks_uri";
    public function run() {
        //$publicKeys = $this->fetchPublicKeys();

        // Here we just pass the jwtToken as a GET
        $jwtToken = $_GET['jwt'];
        if (empty($jwtToken)) {
            echo "No JSON Webtoken given";
            exit();
        }
        $jws = SimpleJWS::load($jwtToken);
        try {
            //echo "Token: " . $jwtToken;
            $allKeys = $this->fetchPublicKeys();
            $keyId = $jws->getHeader()['kid'];
            if ($keyId !== false && is_array($allKeys) && key_exists($keyId, $allKeys)) {
                $keyConf = $allKeys[$keyId];
                $publicKey = $this->getPublicKeyFromExponentAndModulus($keyConf['e'], $keyConf['n']);

                //$decodedToken = JWT::decode($jwtToken, $publicKey, array($keyConf['alg']));


                print '<pre>';
                //var_dump($jws);
                print '</pre>';
                if ($jws->isValid($publicKey, $keyConf['alg']) === false) {
                    echo "Invalid or expired token.";
                }
                $this->printJWS($jws);

            }
        } catch (\Exception $e) {
            print "ERROR!!!: User not authencitaced: " . $e->getMessage();
        }
    }



    /**
     * Get an array of keys  where each index is the KeyID.
     * @todo Make a local cache so we do not look this up every time
     */
    public function fetchPublicKeys() {
        $data = json_decode(file_get_contents(self::CognitoIdentityKeyEndpoint), fasle);
        $publicKeys = array();
        foreach ($data["keys"] as $keyEntry) {
            $publicKeys[$keyEntry['kid']] = $keyEntry;
        }

        //@todo Implement local cache
        return $publicKeys;
    }

    public function getKeyIdFromJWT($token) {
        $parts = explode(".", $token);
        if (count($parts) != 3) {
            return false;
        }
        $decodedHeader = base64_decode($parts[0]);
        if ($decodedHeader === false) {
            return false;
        }
        $decodedHeaderObject = json_decode($decodedHeader, true);
        if ($decodedHeaderObject === false) {
            return false;
        }
        if (is_array($decodedHeaderObject) && key_exists("kid", $decodedHeaderObject)) {
            return $decodedHeaderObject["kid"];
        }
        return false;
    }

    /**
     * @param $modulus
     * @param $exponent
     */
    protected function getPublicKeyFromExponentAndModulus($exponent, $modulus) {
        $rsa = new RSA();
        $modulus = new BigInteger(base64_decode($modulus), 256);
        $exponent = new BigInteger(base64_decode($exponent), 256);
        $rsa->loadKey(array('n' => $modulus, 'e' => $exponent));
        $rsa->setPublicKey();
        return $rsa->getPublicKey();
    }

    /**
     * @param $jws
     */
    protected function printJWS($jws)
    {
        $payload = $jws->getPayload();

        print "<p>User identity: " . $payload['sub'] . '</p>';
        print "<p>Issuer: " . $payload['iss'] . '</p>';
        print "<p>Roles: <ul>";
        foreach ($payload['amr'] as $provider) {
            print '<li>' . $provider . '</li>';
        }
        print '</ul></p>';
        print '<p>Key expires:' . date("d/m-Y H:m:i", $payload['exp']) . '</p>';
        print '<pre>';
        var_dump($payload);
        print '</pre>';
    }
}

$api = new ApiDemo();
$api->run();