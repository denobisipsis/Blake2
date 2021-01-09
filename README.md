# Blake2
PHP Blake2b,Blake2s,Blake2X
https://tools.ietf.org/html/rfc7693

https://www.blake2.net/blake2.pdf

https://www.blake2.net/blake2x.pdf
	  	
Included BLAKE2s, BLAKE 2b & BLAKE2XOF (modes 2b,2s & XOF 0)

Examples:

$data        		        = "";
$key         		        = "";
$salt	     		          = "";
$Personalization      	= ""; 

$b2 = new BLAKE2s($key,$salt,$Personalization);
echo $b2->hash($data);

$b2 = new BLAKE2b($key,$salt,$Personalization);
echo $b2->hash($data);

Extended hashes:

$b2 = new BLAKE2XOF("2s",$key,$salt,$Personalization);
echo $b2->hash($data,XOF length);

$b2 = new BLAKE2XOF("2b",$key,$salt,$Personalization);
echo $b2->hash($data,XOF length);

$b2 = new BLAKE2XOF("2s",$key,$salt,$Personalization);
echo $b2->hash($data,0);

$b2 = new BLAKE2XOF("2b",$key,$salt,$Personalization);
echo $b2->hash($data,0);

Test Vectors included

https://github.com/BLAKE2/BLAKE2/tree/master/testvectors

@denobisipsis 2021
