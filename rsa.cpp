#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

void RSA_Parameter(BIGNUM* p, BIGNUM* q, BIGNUM* n, BIGNUM* d, BIGNUM* e);
void RSA_Encrypt(const BIGNUM* Plain, BIGNUM* Cipher, const BIGNUM* n, const BIGNUM* e);
void RSA_Decipher(const BIGNUM* Cipher, BIGNUM* Plain, const BIGNUM* n, const BIGNUM* d);
void RSA_Decipher_CRT(const BIGNUM* Cipher, BIGNUM* Plain, const BIGNUM* p, const BIGNUM* q, const BIGNUM* d);
void modRepeatSquare(BIGNUM* result, const BIGNUM* b, const BIGNUM* n, const BIGNUM* m);
void CRT(BIGNUM* result, const BIGNUM* y, const BIGNUM* p, const BIGNUM* q, const BIGNUM* pow);
void Montgomerie(BIGNUM* result, const BIGNUM* y, const BIGNUM* pow, const BIGNUM* mod);
void RSA_Encrypt_Montg(const BIGNUM* Plain, BIGNUM* Cipher, const BIGNUM* n, const BIGNUM* e);
void RSA_Decipher_Montg(const BIGNUM* Cipher, BIGNUM* Plain, const BIGNUM* n, const BIGNUM* d);
FILE* File_Key_n, * File_Key_e, * File_Key_d, * File_Plain, * File_Cipter;

int main()
{
	//rsa的参数
	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();
	BIGNUM* n = BN_new();
	BIGNUM* d = BN_new();
	BIGNUM* e = BN_new();

	//明密文
	BIGNUM* Plain = BN_new();
	BIGNUM* Cipher = BN_new();

	clock_t Start;
	clock_t End;

	int j;
	int length;
	char* plainText;

	//将明文k读到spn_key
	File_Plain = fopen("plainText.txt", "r");
	fseek(File_Plain, 0, SEEK_END);
	length = ftell(File_Plain);
	printf("Length:%d\n", length);
	plainText = (char*)malloc(length * sizeof(char));
	fseek(File_Plain, 0, SEEK_SET);
	fgets(plainText, length * sizeof(char), File_Plain);
	fclose(File_Plain);

start:
	printf("\n\nRSARSARSARSARSARSARSARSARSARSARSARSARSARSA\n");
	printf("Please choose the function:\n");
	printf("1. Generate the RSA's parameters\n");
	printf("2. RSA encryption\n");
	printf("3. RSA decryption\n");
	printf("4. RSA CRT decryption\n");
	printf("5. RSA Montgomerie en/decryption\n");
	scanf("%d", &j);
	switch (j) {
	case 1:
	{
		Start = clock();
		RSA_Parameter(p, q, n, d, e);
		printf("Private key(p,q,d): \n");
		printf("p:%s\n\n", BN_bn2hex(p));
		printf("q:%s\n\n", BN_bn2hex(q));
		printf("d:%s\n\n", BN_bn2hex(d));
		printf("Public Key(e,n): \n");
		printf("e:%s\n\n", BN_bn2hex(e));
		printf("n: %s\n\n", BN_bn2hex(n));
		End = clock();
		printf("The time of generating parameters is: %.0lf ms\n", double(End - Start));
	}goto start;
	case 2:
	{
		Start = clock();
        /*BN_bin2bn() converts the positive integer in big-endian form of length len at s 
        into a BIGNUM and places it in ret. 
        If ret is NULL, a new BIGNUM is created.*/
		BN_bin2bn((unsigned char*)plainText, strlen(plainText), Plain); //plainText->plain

		RSA_Encrypt(Plain, Cipher, n, e); // plain->cipher
        printf("Cipher:\n%s\n", BN_bn2hex(Cipher));

		File_Cipter = fopen("theCipherText.txt", "w+");//cipher->theCipherText.txt
		fputs(BN_bn2hex(Cipher), File_Cipter);
		fclose(File_Cipter);

		End = clock();
		printf("The time of encrypting is: %.0lf ms\n", double(End - Start));

	}goto start;
	case 3:
	{
		Start = clock();

		RSA_Decipher(Cipher, Plain, n, d);//cipher->plain
		BN_bn2bin(Plain, (unsigned char*)plainText);//plain->plainText
		printf("Plain:\n%s\n", plainText);

		End = clock();
		printf("The time of decrypting is: %.0lf ms\n", double(End - Start));

		File_Plain = fopen("thePlainText.txt", "w+");//plain->Text->thePlainText.txt
		fputs(plainText, File_Plain);
		fclose(File_Cipter);
	}goto start;
	case 4:
	{
		Start = clock();

		RSA_Decipher_CRT(Cipher, Plain, p, q, d);
		BN_bn2bin(Plain, (unsigned char*)plainText);
		printf("Plain:\n%s\n", plainText);

		End = clock();
		printf("The time of RSA CRT decrypting is: %.0lf ms\n", double(End - Start));
	}goto start;
	case 5:
	{
		Start = clock();

		BN_bin2bn((unsigned char*)plainText, strlen(plainText), Plain);

		RSA_Encrypt_Montg(Plain, Cipher, n, e);
		printf("Cipher:\n%s\n", BN_bn2hex(Cipher));

		End = clock();
		printf("The time of RSA Montgomerie encrypting is: %.0lf ms\n", double(End - Start));

		Start = clock();
		RSA_Decipher_Montg(Cipher, Plain, n, d);
		BN_bn2bin(Plain, (unsigned char*)plainText);
		printf("Plain:\n%s\n", plainText);

		End = clock();
		printf("The time of RSA Montgomerie decryption is: %.0lf ms\n", double(End - Start));


	}goto start;
	default:
	{
		printf("Input Error!\n");
	}
	goto start;
	}
}


void RSA_Parameter(BIGNUM* p, BIGNUM* q, BIGNUM* n, BIGNUM* d, BIGNUM* e) {

	BIGNUM* exp = BN_new();
	BIGNUM* pSub1 = BN_new();
	BIGNUM* qSub1 = BN_new();
	BIGNUM* GCD = BN_new();
	/*上下文情景函数*/
	BN_CTX* ctx = BN_CTX_new();
	/*生成大素数*/
	do
	{
		BN_generate_prime(p, 512, NULL, NULL, NULL, NULL, NULL);
	} while (!BN_is_prime(p, NULL, NULL, NULL, NULL));

	do
	{
		BN_generate_prime(q, 512, NULL, NULL, NULL, NULL, NULL);
	} while (!BN_is_prime(q, NULL, NULL, NULL, NULL));

	BN_mul(n, p, q, ctx);            //n = p * q;
	BN_sub(pSub1, p, BN_value_one()); //pSub1 = p - 1;
	BN_sub(qSub1, q, BN_value_one()); //qSub1 = q - 1;
	BN_mul(exp, pSub1, qSub1, ctx);   //exp = qSub1 * pSub1;
	//辗转相除法
	do
	{
		BN_rand_range(e, exp);
		BN_gcd(GCD, e, exp, ctx);
	} while (BN_cmp(GCD, BN_value_one()));  //得到 e

	while (!BN_mod_inverse(d, e, exp, ctx));    //得到 d

	BN_CTX_free(ctx);
	BN_free(GCD);
	BN_free(qSub1);
	BN_free(pSub1);
	BN_free(exp);
}

void RSA_Encrypt(const BIGNUM* Plain, BIGNUM* Cipher, const BIGNUM* n, const BIGNUM* e)
{
	modRepeatSquare(Cipher, Plain, e, n);//膜重复平方--cipher = plain^e(mod n)
}

void RSA_Decipher(const BIGNUM* Cipher, BIGNUM* Plain, const BIGNUM* n, const BIGNUM* d)
{
	modRepeatSquare(Plain, Cipher, d, n);//膜重复平方--plain = Cipher^d(mod n)
}

void RSA_Decipher_CRT(const BIGNUM* Cipher, BIGNUM* Plain, const BIGNUM* p, const BIGNUM* q, const BIGNUM* d)
{
	CRT(Plain, Cipher, p, q, d);
}

void RSA_Encrypt_Montg(const BIGNUM* Plain, BIGNUM* Cipher, const BIGNUM* n, const BIGNUM* e)
{
	Montgomerie(Cipher, Plain, e, n);
}

void RSA_Decipher_Montg(const BIGNUM* Cipher, BIGNUM* Plain, const BIGNUM* n, const BIGNUM* d)
{
	Montgomerie(Plain, Cipher, d, n);
}


void modRepeatSquare(BIGNUM* result, const BIGNUM* b, const BIGNUM* pow, const BIGNUM* mod)
{
    //Result为结果，b为底数，Pow为幂，Mod为模
	BIGNUM* divRes = BN_new();
	BIGNUM* tempB = BN_new();
	BIGNUM* tempPow = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* aNew = BN_new();
	BIGNUM* bSqr = BN_new();
	BIGNUM* rem = BN_new();
	BIGNUM* Two = BN_new();

	BN_CTX* ctx = BN_CTX_new();

	BN_copy(tempB, b); //cup_b <- b
	BN_copy(tempPow, pow);

	BN_set_word(aNew, 1);
	BN_set_word(Two, 2);
    /*膜重复平方*/
	do {
        /* int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx); dv=a/d, rem=a%d*/
		BN_div(divRes, rem, tempPow, Two, ctx);
		if (BN_is_one(rem))  BN_mod_mul(a, aNew, tempB, mod, ctx);//rem = 1
		else BN_copy(a, aNew);//rem = 0

		BN_mod_sqr(bSqr, tempB, mod, ctx);

		BN_copy(aNew, a);
		BN_copy(tempPow, divRes);
		BN_copy(tempB, bSqr);

	} while (!BN_is_zero(divRes));

	BN_copy(result, a);//将结果存在result中

	BN_CTX_free(ctx);
	BN_free(Two);
	BN_free(rem);
	BN_free(bSqr);
	BN_free(aNew);
	BN_free(a);
	BN_free(tempPow);
	BN_free(tempB);
	BN_free(divRes);
}

void CRT(BIGNUM* result, const BIGNUM* y, const BIGNUM* p, const BIGNUM* q, const BIGNUM* pow)
{
    /*result = y^pow(mod p * q);
    result为结果, y为底数, p and q为大素数, Pow为幂
    解密rsa的流程c^d mod n,可以分解为 m1=c^d mod p以及m2=c^d mod q方程组
    但是等式c^d mod p 或者 c^d mod q ，模数虽然从n降为p或q了，但是这个指数d还是较大，运算还是比较消耗性能。
    所以 c^d mod p可以降阶为 c^(d mod p-1) mod p. 同理，c^d mod q可以降阶为 c^(d mod q-1) mod q*/
    BIGNUM* Cp = BN_new();
	BIGNUM* Cq = BN_new();
	BIGNUM* c1 = BN_new();
	BIGNUM* c2 = BN_new();
	BIGNUM* Pow1 = BN_new();
	BIGNUM* Pow2 = BN_new();
	BIGNUM* x11 = BN_new();
	BIGNUM* x12 = BN_new();
	BIGNUM* x21 = BN_new();
	BIGNUM* x22 = BN_new();
	BIGNUM* pSub1 = BN_new();
	BIGNUM* qSub1 = BN_new();
	BIGNUM* mod = BN_new();

	BN_CTX* ctx = BN_CTX_new();

    BN_mul(mod, p, q, ctx); //mod = p * q;

    BN_sub(pSub1, p, BN_value_one()); //pSub1 = p - 1;
    BN_sub(qSub1, q, BN_value_one()); //qSub1 = q - 1;
    //中国剩余定理加速
    BN_nnmod(Pow1, pow, pSub1, ctx); //pow1 = pow(mod p-1);
    BN_nnmod(Pow2, pow, qSub1, ctx); //pow2 = pow(mod q-1);

    modRepeatSquare(Cp, y, Pow1, p); // cp = y^pow1(mod p);
    modRepeatSquare(Cq, y, Pow2, q); // cq = y^pow2(mod q);
    //处理完毕, 下面为中国剩余定理
    BN_mod_inverse(c1, q, p, ctx); // c1 * q = 1(mod p);
    BN_mod_inverse(c2, p, q, ctx); // c2 * p = 1(mod q);
    //计算中国剩余定理: b1 * M1 * M1-1 + b2 * M2 * M2-1
    BN_mul(x11, Cp, c1, ctx);
    BN_mul(x12, x11, q, ctx); // x12 = cp * c1 * q;
    BN_mul(x21, Cq, c2, ctx);
    BN_mul(x22, x21, p, ctx); // x22 = cq * c2 * p;

    BN_mod_add(result, x12, x22, mod, ctx); //result = x12 + x22;

    BN_CTX_free(ctx);
	BN_free(qSub1);
	BN_free(pSub1);
	BN_free(x22);
	BN_free(x21);
	BN_free(x12);
	BN_free(x11);
	BN_free(Pow2);
	BN_free(Pow1);
	BN_free(c2);
	BN_free(c1);
	BN_free(Cq);
	BN_free(Cp);

}

void Montgomerie(BIGNUM* result, const BIGNUM* b, const BIGNUM* pow, const BIGNUM* mod)
{
    //Result为结果, b为底数, pow为幂, mod为模
	BIGNUM* res = BN_new();
	BIGNUM* Two = BN_new();
	BIGNUM* Zero = BN_new();
	BIGNUM* tempNumb = BN_new();
	BIGNUM* tempPow = BN_new();
	BN_CTX* ctx = BN_CTX_new();

    //快速计算 result = b ^ pow (mod mod);
    BN_one(result); // result = mont(1);
    BN_set_word(Zero, 0);
	BN_set_word(Two, 2);
    BN_copy(res, b); // res = mont(b);
    BN_copy(tempPow, pow); // tempPow = pow;

    while (BN_cmp(tempPow, Zero) == 1) // while(e != 0);
    {
        BN_mod(tempNumb, tempPow, Two, ctx); // tempNumb = tempPow(mod 2);

        if (BN_is_zero(tempNumb)) // if(tempNumb = 0(mod 2));
        {
            //prod = montmult(prod, a);
            BN_mod_sqr(tempNumb, res, mod, ctx); //tempNumb = res^2(mod mod);
            BN_copy(res, tempNumb);              //res = tempNumb;

            BN_div(tempNumb, NULL, tempPow, Two, ctx);
            BN_copy(tempPow, tempNumb);
        }
        else
        {
            BN_mod_mul(tempNumb, result, res, mod, ctx);
            BN_copy(result, tempNumb); //result = result * res (mod mod);

            BN_sub(tempNumb, tempPow, BN_value_one());
            BN_copy(tempPow, tempNumb); // tempPow(e) = tempPow(e) - 1;
        }
    }

	BN_CTX_free(ctx);
	BN_free(tempPow);
	BN_free(tempNumb);
	BN_free(Zero);
	BN_free(Two);
	BN_free(res);
}