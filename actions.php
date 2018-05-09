<?php

$coreData = array();

$reqMethod = $_SERVER['REQUEST_METHOD'];
$isPost = $reqMethod === "POST";

$arr = $isPost ? @$_POST : @$_GET;

$action = $arr['action'];

$defaultCase = false;
$forceHeader = true;

if(!checkEmpty($arr, $action)) 
{
	switch ($reqMethod) {
		case 'POST':
			$token = @$_POST['token'];

			switch ($action) 
			{
				case 'check-user':
					//Add user if not exists
					/*
					  `username` text NOT NULL,
					  `password` text NOT NULL,
					  `email` text NOT NULL,
					  `receivemails` tinyint(1) NOT NULL,
					  `ip` varchar(15) NOT NULL, //Not parameter
					  `pcid` text NOT NULL,
					  `reg_date` date NOT NULL, //Now
					  `last_activity` date NOT NULL, //Now
					  `launcher_version` text NOT NULL,
					  `lang_used` varchar(2) NOT NULL,
					  `play_hits` int(11) NOT NULL, //Not parameter = 0
					  `launcher_hits` int(11) NOT NULL, //Not parameter = 0
					  `os` text NOT NULL,
					  `resolution` text NOT NULL,
					  `cpu_name` text NOT NULL,
					  `ram` int(11) NOT NULL,
					  `main_hdd` text NOT NULL
					*/
					break;

				case 'check-visitor':
					//Add visitor if not exists, and return data even it if exists or not
					/*
					  `ip` varchar(15) NOT NULL,
					  `pcid` text NOT NULL,
					  `reg_date` date NOT NULL,
					  `played_time` date NOT NULL,
					  `last_activity` date NOT NULL,
					  `launcher_version` text NOT NULL,
					  `lang_used` varchar(2) NOT NULL,
					  `play_hits` int(11) NOT NULL,
					  `launcher_hits` int(11) NOT NULL,
					  `os` text NOT NULL,
					  `resolution` text NOT NULL,
					  `cpu_name` text NOT NULL,
					  `ram` int(11) NOT NULL COMMENT 'In MB',
					  `main_hdd` text NOT NULL
					*/
					break;

				case 'playhit':
					//Register hit for that user for play button
					break;

				case 'launcherhit':
					//The same as before, but for launcher only
					break;

				case 'not-afk':
					//Tell the DB we aren't offline and update current value of online users in DB (actual_ccusers)
					//and if we are playing update played time from user (we have to detect if we are playing)
					break;

                case "resolve-captcha":
                    if(session_status() == PHP_SESSION_NONE)
                    {
                        //session_name("CookieName");
                        session_start(); //addError("noSession");
                    }

                    $secret = @$_SESSION["phrase"]; //@$_POST["secret"];

                    if(empty($secret))
                        die("No secret!");

                    //$coreData["secret"] = $secret;

                    $input = @$_POST["input"];

                    $coreData["valid"] = $input === $secret;
                    break;

				default:
					$defaultCase = true;
					break;
			}
			break;

		case 'GET':
			switch ($action) 
			{
				case 'secret':
				    //Aqui deberiamos usar algo de jwt

					//We get here the token for every petition
					//First step: give a random string and store it on a SecureString (C#)
					//Second step: Generate a token in both (client & server) and validate client token with server one
				
					//Secret would be random string given from the first step of this case
					$coreData["secret"] = bin2hex(openssl_random_pseudo_bytes(16));

					//I should use free https to avoid security problems through sniffing packets
					break;

                /*case 'pubkey':
                    $pkGeneratePrivate = file_get_contents("private.key");

                    // generate 2048-bit RSA key
                    $pkGenerate = openssl_pkey_new(array(
                        'private_key_bits' => 2048,
                        'private_key_type' => OPENSSL_KEYTYPE_RSA
                    ));

                    // get the private key
                    openssl_pkey_export($pkGenerate,$pkGeneratePrivate); // NOTE: second argument is passed by reference

                    // get the public key
                    $pkGenerateDetails = openssl_pkey_get_details($pkGenerate);
                    $pkGeneratePublic = $pkGenerateDetails['key'];

                    // free resources
                    openssl_pkey_free($pkGenerate);

                    // fetch/import public key from PEM formatted string
                    // remember $pkGeneratePrivate now is PEM formatted...
                    // this is an alternative method from the public retrieval in previous
                    $pkImport = openssl_pkey_get_private($pkGeneratePrivate); // import
                    $pkImportDetails = openssl_pkey_get_details($pkImport); // same as getting the public key in previous
                    $pkImportPublic = $pkImportDetails['key'];
                    openssl_pkey_free($pkImport); // clean up

                    // let's see 'em
                    echo "\n".$pkGeneratePrivate
                        ."\n".$pkGeneratePublic
                        ."\n".$pkImportPublic
                        ."\n".'Public keys are '.(strcmp($pkGeneratePublic,$pkImportPublic)?'different':'identical').'.';
                    break;*/

                case "genkeys":
                    include("includes/auth.php");

                    $time_start = microtime(true);
                    include('phpseclib/rsa_autoload.php');

                    $rsa = new phpseclib\Crypt\RSA();
                    //$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_OPENSSH);
                    $result = $rsa->createKey(4096);

                    $fp = fopen($privFile, 'w') or die("File not found!");
                    fwrite($fp, $result["privatekey"]);
                    fclose($fp);

                    $fp = fopen($pubFile, 'w') or die("File not found!");
                    fwrite($fp, $result["publickey"]);
                    fclose($fp);

                    $coreData["executionTime"] = (int)((microtime(true) - $time_start) * 1000);
                    break;

                case "pubkey":
                    //$coreData["privKey"] = file_get_contents("keys/private.key");
                    $coreData["pubKey"] = file_get_contents("keys/public.key");
                    break;

                case "captcha":
                    if (session_status() == PHP_SESSION_NONE)
                        session_start();

                    //$forceHeader = false;
                    include("libs/captcha/autoload.php");

                    $builder = new Gregwar\Captcha\CaptchaBuilder;
                    $builder->build();

                    ob_start();
                    $builder->output();
                    $imageString = ob_get_clean();

                    $phrase = $builder->getPhrase();
                    $_SESSION['phrase'] = $phrase;

                    $coreData["jpeg"] = base64_encode($imageString);
                    //$coreData["md5"] = md5($phrase);
                    break;

                case "compute":
                    include("includes/auth.php");
                    $time_start = microtime(true);

                    $num = 100000;
                    $i = 0;
                    $addalphabeth = array_merge(range('a', 'z'), range(0,9));
                    $txt = "";

                    $setcharacter = [];
                    foreach ($addalphabeth as $setcharacter[0]) {
                        foreach ($addalphabeth as $setcharacter[1]) {
                            foreach ($addalphabeth as $setcharacter[2]) {
                                foreach ($addalphabeth as $setcharacter[3]) {
                                    foreach ($addalphabeth as $setcharacter[4]) {
                                        $str = vsprintf('%s%s%s%s%s', $setcharacter);

                                        $txt .= $str." - ".md5($str).PHP_EOL;

                                        ++$i;
                                        if($i == $num)
                                        {
                                            break 5;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    file_put_contents('results/md5.txt', $txt);

                    $coreData["executionTime"] = (int)((microtime(true) - $time_start) * 1000);
                    break;

                    //This goes to POST
                case 'decrypt':
                    include("libs/jose/autoload.php");

                    // We load our private RSA key.
                    $jwk = Jose\Factory\JWKFactory::createFromKeyFile(
                        'keys/private.key',
                        'Password',
                        [
                            'kid' => 'My Private RSA key',
                            'use' => 'enc',
                            'alg' => 'RSA-OAEP',
                        ]
                    );

                    // We create our loader.
                    $loader = new Jose\Loader();

                    // This is the input we want to load verify.
                    $input = @$_GET["input"];

                    // The payload is decrypted using our key.
                    $jws = $loader->loadAndDecryptUsingKey(
                        $input,            // The input to load and decrypt
                        $jwk,              // The symmetric or private key
                        ['RSA-OAEP'],      // A list of allowed key encryption algorithms
                        ['A256GCM'],       // A list of allowed content encryption algorithms
                        $recipient_index   // If decrypted, this variable will be set with the recipient index used to decrypt
                    );
                    break;

				default:
					$defaultCase = true;
					break;
			}
			break;
		
		default:
			addError("undefinedMethod", $reqMethod);
			break;
	}

	if($defaultCase)
		addError("undefinedCase", $action, $reqMethod);
}
else 
{
	die("Action is null!");
}