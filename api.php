<?php

//Iniciamos errores

include('includes/error_manager.php');

include('autoload.php');

include('includes/actions.php');

//actions_main($coreData);

if($forceHeader)
{
    header('Content-Type: application/json');
    die(showJson($coreData));
}

//Cerramos y mostramos errores