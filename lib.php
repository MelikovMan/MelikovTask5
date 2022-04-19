<?php 
function connectToDB($user,$pass){
    $db = new PDO('mysql:host=localhost;dbname=u47551', $user, $pass, array(PDO::ATTR_PERSISTENT => true));
    return $db;
}
?>