<?php

/**
 * Файл login.php для не авторизованного пользователя выводит форму логина.
 * При отправке формы проверяет логин/пароль и создает сессию,
 * записывает в нее логин и id пользователя.
 * После авторизации пользователь перенаправляется на главную страницу
 * для изменения ранее введенных данных.
 **/

// Отправляем браузеру правильную кодировку,
// файл login.php должен быть в кодировке UTF-8 без BOM.
header('Content-Type: text/html; charset=UTF-8');

// Начинаем сессию.
session_start();

// В суперглобальном массиве $_SESSION хранятся переменные сессии.
// Будем сохранять туда логин после успешной авторизации.
if (!empty($_SESSION['login'])) {
  // Если есть логин в сессии, то пользователь уже авторизован.
  // TODO: Сделать выход (окончание сессии вызовом session_destroy()
  //при нажатии на кнопку Выход).
  // Делаем перенаправление на форму.
  header('Location: ./');
}
if(!empty($_COOKIE('bad_login'))){
    setcookie('bad_login','',100000);
    $badloging = true;
}
else $badloging = false;
// В суперглобальном массиве $_SERVER PHP сохраняет некторые заголовки запроса HTTP
// и другие сведения о клиненте и сервере, например метод текущего запроса $_SERVER['REQUEST_METHOD'].
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
?>

<form action="" method="post" <?php if ?>>
  <input name="login" />
  <input name="pass" />
  <input type="submit" value="Войти" />
</form>
<?php if($badloging) print('<div> Invalid login! </div') ?>
<?php
}
// Иначе, если запрос был методом POST, т.е. нужно сделать авторизацию с записью логина в сессию.
else {
    $user = 'u47551';
    $pass = '4166807';
    $db = new PDO('mysql:host=localhost;dbname=u47551', $user, $pass, array(PDO::ATTR_PERSISTENT => true));
		try {
			$stmt = $db->prepare("SELECT pass_hash, p_id FROM login WHERE login=:this_login");
			$stmt->bindParam(':this_login',$_POST['login']);
			if($stmt->execute()==false) {
				print_r($stmt->errorCode());
				print_r($stmt->errorInfo());
				exit();
			}
            catch(PDOException $e){
                print('Error : ' . $e->getMessage());
                exit();
            }
	$dbread=array();
	$dbread=$stmt->fetch(PDO::FETCH_ASSOC);
    if(!password_verify($_POST['pass'],$dbread['pass_hash'])){
        setcookie('bad_login',1,time() + 30 * 24 * 60 * 60));
        header('Location: ./login.php');   

    }
    else{
  // TODO: Проверть есть ли такой логин и пароль в базе данных.
  // Выдать сообщение об ошибках.

  // Если все ок, то авторизуем пользователя.
  $_SESSION['login'] = $_POST['login'];
  // Записываем ID пользователя.
  $_SESSION['uid'] = $dbread['p_id'];
  // Делаем перенаправление.
  header('Location: ./');
    }
}