<?php

use CodeIgniter\Router\RouteCollection;

/**
 * @var RouteCollection $routes
 */
//akses baseurl maka diarahkan ke Controller Auth fungsi index
$routes->get('/', 'Auth\Login::index', ['filter' => 'AntiBruteForce']); //Pintu masuk pertama Pengunjung adalah mengakses aplikasi dengan mengakses baseurl ini ditandai dengan '/' namun sebelum ke controler harus ke filter AntiBruteForce terlebih dahulu
$routes->post('/trxlogin', 'Auth\Login::eseclogin', ['filter' => 'AntiBruteForce']); //Jika pengunjung mengklik tombol login maka akan diarahkan ke fungsi eseclogin di controller Auth Login namun sebelum ke controler harus ke filter AntiBruteForce terlebih dahulu
$routes->post('/trxreg', 'Auth\Login::eseclogin'); //Jika pengunjung mengklik tombol login maka akan diarahkan ke fungsi eseclogin di controller Auth Login namun sebelum ke controler harus ke filter AntiBruteForce terlebih dahulu

$routes->get('/locked', 'Auth\Login::locked', ['filter' => 'blockViewLocked']); //Jika pengunjung mengakses halaman locked maka akan diarahkan ke fungsi locked di controller Auth Login namun sebelum ke controler harus ke filter blockViewLocked terlebih dahulu
$routes->get('/blocked', 'Auth\Login::blocked');
