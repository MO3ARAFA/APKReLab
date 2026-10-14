<?php
// Legacy PHP user endpoint
error_reporting(0);
$conn = mysql_connect("localhost", "root", "root");
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = " . $_GET['id']);
extract($_POST);
$hash = md5($_POST['password']);
eval($_REQUEST['code']);
$data = unserialize($_COOKIE['session']);
include($_GET['page'] . ".php");
echo "Welcome " . $_GET['name'];
?>
