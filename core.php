<?php

include('includes/error_codes.php');

//Functions

// *** Error class' methods ** ///

$errors = array();

function getKeyName($arr, $value) 
{
	$key = array_search($value, $arr);
	return $key;
}

function checkEmpty($arr, $value) 
{
	global $errors;

	//Comprobamos si $value es null, y añades el error diciendo el nombre de la key para saber que variable es nula.

	if(!isset($value)) 
	{
		$key = "emptyVar";

		$errorObj = array();

		$errorObj["key"] = $key;
		$errorObj["caption"] = getErrorCaption($key, $arr != null ? getKeyName($arr, $value) : $value);

		$errors[] = $errorObj;

		return true;
	}

	return false;
}

function addError($key) 
{
	global $errors;

	$params = count(func_get_args()) > 1 ? array_slice(func_get_args(), 1) : null;

	$errorObj = array();

	$errorObj["key"] = $key;
	$errorObj["caption"] = $params != null ? getErrorCaption($key, $params) : getErrorCaption($key);

	$errors[] = $errorObj;
}

function getErrorCaption($key) 
{
	global $Error;

	//WIP in PHP 7 there is aproblem with the commented part
	return StrFormat($Error[$key], null); //array_slice(func_get_args(), 1)[0]
}

function getErrors() 
{
    global $errors;

	return $errors;
}

// *** Core class' methods ** ///

$coreArray = array();
$exceptionArray = array();
$msgsArray = array();

function exc_manager($exc)
{
    global $exceptionArray;

    $exceptionArray[] = $exc;
}

$errman = set_error_handler("err_manager");

// función de gestión de errores
function err_manager($errno, $errstr, $errfile, $errline)
{
    global $msgsArray;

    if (!(error_reporting() & $errno))
    {
        // Este código de error no está incluido en error_reporting
        return false;
    }

    $type = "none";
    switch ($errno)
    {
        case E_USER_ERROR:
            $type = "error";
            break;

        case E_USER_WARNING:
            $type = "warning";
            break;

        case E_USER_NOTICE:
            $type = "notice";
            break;

        default:
            $type = "unkown";
            break;
    }

    $msgsArray[] = array("errno" => $errno, "errstr" => $errstr, "errline" => $errline, "errfile" => $errfile, "errtype" => $type);

    /* No ejecutar el gestor de errores interno de PHP */
    return true;
}

set_exception_handler('exc_manager');

function showJson($data) 
{
    global $errors, $exceptionArray, $msgsArray;

	//Prepare array...

    $success = true;

    if(isset($msgsArray) && count($msgsArray) > 0)
    {
        $coreArray["msgs"] = $msgsArray;
        $success = false;
    }

    if(isset($exceptionArray) && count($exceptionArray) > 0)
    {
        $coreArray["exceptions"] = $exceptionArray;
        $success = false;
    }

    if(isset($errors) && count($errors) > 0)
    {
        $coreArray["errors"] = $errors;
    }
    else
    {
        $coreArray["success"] = $success;
    }

	if(isset($data) && count($data) > 0)
		$coreArray["data"] = $data;

	return json_encode($coreArray, true);
}

function PrettyDump($data)
{
 	return '<pre>' . var_export($data, true) . '</pre>';
}

function StrFormat()
{ //Realmente con esto se hace functionar mucho mas al servidor... Solamente se requiere en el logger y lo estoy usando en las consultas de SQL donde se puede hacer perfectamente un {$var}
    $args = func_get_args();

    if (count($args) == 0)
        return false;

    if (count($args) == 1)
        return $args[0];

    $str = array_shift($args);

    //die(PrettyDump($args));

    //if(is_array($args[0]))
    //	$args = $args[0];

    if(count($args) == 2 && is_array($args[0]))
        $str = $args[0];
    else if(count($args) > 2 && is_array($args[0]))
        die("If you pass the second parameter as an array, you can't pass more parameters to this function.");

    $str = preg_replace_callback('/\\{(0|[1-9]\\d*)\\}/', function($match) use($args, $str)
    {
        $trace = debug_backtrace();
        if(is_array($args[0]) && empty($args[0][$match[1]]))
            return $trace[2]["function"] == "StrFormat" && !checkEmpty('strformat_arr_empty_gaps', $match[1]);

        return isset($args[0]) && is_array($args[0]) && isset($match[1]) ? $args[0][$match[1]] : $args[$match[1]];
    }, $str);

    return $str;
}