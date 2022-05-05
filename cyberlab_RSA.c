#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM * a)
{
char * number_str = BN_bn2dec(a);
printf("%s\n",msg );
printf("%s\n", number_str);

OPENSSL_free(number_str);
}
int main ()
{
BN_CTX *ctx = BN_CTX_new();
BIGNUM *p = BN_new();
BIGNUM *d = BN_new();
BIGNUM *q = BN_new();
BIGNUM *n = BN_new();
BIGNUM *M = BN_new();
BIGNUM *E= BN_new();
BIGNUM *res = BN_new();
BIGNUM *temp1 = BN_new();
BIGNUM *temp2 = BN_new();
BIGNUM *tont=BN_new();
BIGNUM *e= BN_new();
BIGNUM *big_one = BN_new();

BN_dec2bn(&big_one,"1");

BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
BN_mul(n,q,p,ctx);
BN_hex2bn(&e,"0D88C3");

BN_sub(temp1,p,big_one);
BN_sub(temp2,q,big_one);
BN_mul(tont,temp1,temp2,ctx);
BN_mod_inverse(d,e,tont,ctx);

printBN("\nThe private key is : \n",d);
BN_hex2bn(&M,"4120746f702073656372657421");
BN_mod_exp(E,M,e,n,ctx);
printBN("\nThe encrypted message is: \n",E);
BN_mod_exp(res,E,d,n,ctx);
printBN("\nThe decrypted message: \n",res);

BN_hex2bn(&res,"4120746f702073656372657421");

printBN("\nOriginal binary format message:\n",res);



return 0;
}










