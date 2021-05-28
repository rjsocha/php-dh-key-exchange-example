#!/usr/bin/php
<?php
function dump_openssl_errors($info) {
	printf("%s:\n",$info);
	while ($msg = openssl_error_string()) {
		printf("\t%s\n",$msg);
	}
	die();
}

// defincja parametrów DH (z RFC)
require('rfc7919.inc');

if($argc>1) {
	$dhp=strval($argv[1]);
	if(!array_key_exists($dhp,$_ffdhe)) {
		printf("Parametry DH o rozimiarze %s nie są zdefiniowane...\n",$dhp);
		exit(1);
	}
} else {
	$dhp='4096';
}

// generacja klucza
printf("DH Param size: %s bits\n",$dhp);
printf("PEER 1: genracja klucza prywatnego DH: ");
if(($peer1_pk=openssl_pkey_new(array('dh' => $_ffdhe[$dhp])))===false) dump_openssl_errors("error");
printf("OK\n");

printf("PEER 2: genracja klucza prywatnego DH: ");
if(($peer2_pk=openssl_pkey_new(array('dh' => $_ffdhe[$dhp])))===false) dump_openssl_errors("error");
printf("OK\n");

printf("PEER1: uzyskanie klucza publicznego DH: ");
if(($peer1_details = openssl_pkey_get_details($peer1_pk))===false) dump_openssl_errors("error");
if(!isset($peer1_details['dh']['pub_key'])) {
	printf("PEER1: brak klucza publicznego?\n");
	exit(10);
}
printf("OK\n");
$peer1_pub_key=$peer1_details['dh']['pub_key'];

printf("PEER2: uzyskanie klucza publicznego DH: ");
if(($peer2_details = openssl_pkey_get_details($peer2_pk))===false) dump_openssl_errors("error");
if(!isset($peer2_details['dh']['pub_key'])) {
	printf("PEER2: brak klucza publicznego?\n");
	exit(10);
}
printf("OK\n");
$peer2_pub_key=$peer2_details['dh']['pub_key'];

printf("\n");
printf("PEER1 Public: %s\n",bin2hex($peer1_pub_key));
printf("\n");
printf("PEER2 Public: %s\n",bin2hex($peer2_pub_key));
printf("\n");

printf("PEER1: Generacja wspólnego klucza sesyjnego: ");
if(($shared1 = openssl_dh_compute_key($peer2_pub_key, $peer1_pk))===false) dump_openssl_errors("error");
printf("OK\n");

printf("PEER2: Generacja wspólnego klucza sesyjnego: ");
if(($shared2 = openssl_dh_compute_key($peer1_pub_key, $peer2_pk))===false) dump_openssl_errors("error");
printf("OK\n");

printf("\n");
printf("SECRET1: %s\n",bin2hex($shared1));
printf("\n");
printf("SECRET2: %s\n",bin2hex($shared2));

printf("\n");

if($shared1==$shared2) {
	printf("Klucze zgodne!\n");
} else {
	printf("Klucze nie są zgodne!\n");
}
