<?php
/**
 * Created by PhpStorm.
 * User: Álvaro
 * Date: 09/05/2018
 * Time: 17:41
 */

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

//set_exception_handler('exc_manager');