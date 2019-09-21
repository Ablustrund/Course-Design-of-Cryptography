#define _CRT_SECURE_NO_WARNINGS
#include "stdio.h"
#include "stdlib.h"
#include "time.h"
#include "math.h"
#include <windows.h>
#include<iostream>
#include<conio.h>
using namespace std;

#define Len     16
#define True    1
#define False   0

void hexToBit(int In[], int* Out, int Length);    //16进制转2进制
void bitToHex(int* In, int* Out, int Length);    //2进制转16进制
void Copy(int* In, int* Out, int Length);

void SPN_Start(int* MesIn, int* MesOut, int K[]);
void SPN_XOR(int* DataA, int* DataB);            //异或
void SPN_Trans(int* In, int* Out, int* Change);   //P盒置换
void SPN_Change(int* In, int* Change);           //S盒代替
void SPN_K(int K[]);           //处理轮密钥K

void SPN_LineAttack(int* KeyOut, int Length);       //线性攻击
void SPN_DifAnalysis(int* KeyOut, int Length);      //差分分析
void RanText(int* In, int* Out, int Key[]);
void ViolentCrack(int* KeyOut);

void FileEncryption(char *PlainFileName, char *CipherFileName, int *Key);
//void DEC(FILE *PlainFile, FILE* CipherFile, int* Key);
void FileDecryption(char* PlainFileName, char* CipherFileName, int *Key);
void BlockEncryption(char *PlainText, char *CipherText, int *Key);
void BlockDecryption(char *PlainText, char *CipherText, int *Key);

typedef struct tagciphertextinfo {
    char *filename;
	int  w;
    int  v;
} ciphertextinfo;

static int SBox_Plus[256]={
    82, 9, 106, 213, 48, 54, 165, 56, 191,
    64, 163, 158, 129, 243, 215, 251, 124,
    227, 57, 130, 155, 47, 255, 135, 52,
    142, 67, 68, 196, 222, 233, 203, 84,
    123, 148, 50, 166, 194, 35, 61, 238,
    76, 149, 11, 66, 250, 195, 78, 8,
    46, 161, 102, 40, 217, 36, 178, 118,
    91, 162, 73, 109, 139, 209, 37, 114,
    248, 246, 100, 134, 104, 152, 22, 212,
    164, 92, 204, 93, 101, 182, 146, 108,
    112, 72, 80, 253, 237, 185, 218, 94,
    21, 70, 87, 167, 141, 157, 132, 144,
    216, 171, 0, 140, 188, 211, 10, 247,
    228, 88, 5, 184, 179, 69, 6, 208,
    44, 30, 143, 202, 63, 15, 2, 193,
    175, 189, 3, 1, 19, 138, 107, 58,
    145, 17, 65, 79, 103, 220, 234, 151,
    242, 207, 206, 240, 180, 230, 115, 150,
    172, 116, 34, 231, 173, 53, 133, 226,
    249, 55, 232, 28, 117, 223, 110, 71,
    241, 26, 113, 29, 41, 197, 137, 111,
    183, 98, 14, 170, 24, 190, 27, 252,
    86, 62, 75, 198, 210, 121, 32, 154,
    219, 192, 254, 120, 205, 90, 244, 31,
    221, 168, 51, 136, 7, 199, 49, 177,
    18, 16, 89, 39, 128, 236, 95, 96,
    81, 127, 169, 25, 181, 74, 13, 45,
    229, 122, 159, 147, 201, 156, 239, 160,
    224, 59, 77, 174, 42, 245, 176, 200,
    235, 187, 60, 131, 83, 153, 97, 23,
    43, 4, 126, 186, 119, 214, 38, 225,
    105, 20, 99, 85, 33, 12, 125
};

static int PBox_Plus[64]=
{
    0, 8, 16, 24, 32, 40, 48, 56,
    1, 9, 17, 25, 33 ,41, 49, 57,
    2, 10,18, 26, 34, 42, 50, 58,
    3, 11,19, 27, 35, 43, 51, 59,
    4, 12,20, 28, 36, 44, 52, 60,
    5, 13,21, 29, 37, 45, 53, 61,
    6, 14,22, 30, 38, 46, 54, 62,
    7, 15,23, 31, 39, 47, 55, 63
};

static int SBox_Plus_Opposite[256]=
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
	0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
	0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
	0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
	0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
	0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
	0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
	0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
	0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
	0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
	0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
	0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
	0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
	0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
	0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
	0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
	0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static int PBox_Plus_Opposite[64]=
{
    0, 8, 16, 24, 32, 40, 48, 56,
    1, 9, 17, 25, 33 ,41, 49, 57,
    2, 10,18, 26, 34, 42, 50, 58,
    3, 11,19, 27, 35, 43, 51, 59,
    4, 12,20, 28, 36, 44, 52, 60,
    5, 13,21, 29, 37, 45, 53, 61,
    6, 14,22, 30, 38, 46, 54, 62,
    7, 15,23, 31, 39, 47, 55, 63
};

static int Key_plus[]={0x3A,0x79,0x34,0x5D,0x16,0x33,0x9F,0x47,0x22,0x4E,0x54,0x92,0x61,0x1A,0x56,0x71,0x6B,0x2C,0x73,0x65,0x84,0x48,0x16,0x55,0xC4,0x61,0x87,0x99};

static int K[32] =
{ 0,0,0,0,1,0,1,0,1,0,0,1,0,1,0,0,1,1,0,1,0,1,1,0,0,0,1,0,1,1,1,1 };

static int SBox[Len] = {
14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 };

static int PBox[Len] = {
1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16 };

static int SBox_Opposite[Len] = {
14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5 };

static int Key[5][Len] = { 0 };

static int KeyTest[32] = { 0 };
int main()
{
	int i, j;
	int MesIn[Len] = { 0,0,1,0,0,1,1,0,1,0,1,1,0,1,1,1 };
	int MesOut[Len] = { 0 };
	clock_t Start, End;
	char *PlainFile = "book.txt";      //源文件地址
    char *CipherFile = "file_enc.txt"; //加密后文件地址
    char *DecFile = "file_dec.txt";    //解密后文件地址

start:
	printf("\n");
	printf("Please choose the functions\n");
	printf("1. Spn encryption\n");
	printf("2. Linear analysis\n");
	printf("3. Differential analysis\n");
	printf("4. Differential decryption\n");
	printf("5. Spn encryption-plus\n");
    printf("6. Spn decryption-plus\n");
	scanf("%d", &j);
	switch (j) {
	case 1:
	{
		Start = clock();
		//printf("please input the plain text:\n");
		//for(i=0;i<Len;i++)   scanf("%d",&MesIn[i]);
		for(i=0;i<Len;i++)
			printf("%d",MesIn[i]);

		SPN_Start(MesIn, MesOut, K);
		printf("\nThe result of the encryption is: \n");
		for (i = 0; i < Len; i++)
			printf("%d", MesOut[i]);
		printf("\n");

		End = clock();
		printf("The time of the encryption is: %.0lf ms\n\n", double(End - Start));

	}goto start;
	case 2:
	{
		Start = clock();

		printf("The subkey is: \n");
		SPN_LineAttack(KeyTest, 8000);
		for (i = 20; i < 24; i++)
			printf("%d", KeyTest[i]);
		for (i = 28; i < 32; i++)
			printf("%d", KeyTest[i]);
		printf("\n");

		End = clock();
		printf("The time of linear attack is: %.0lf ms\n\n", double(End - Start));
	}goto start;
	case 3:
	{
		Start = clock();

		printf("The subkey is: \n");
		SPN_DifAnalysis(KeyTest, 500);
		for (i = 20; i < 24; i++)
			printf("%d", KeyTest[i]);
		for (i = 28; i < 32; i++)
			printf("%d", KeyTest[i]);
		printf("\n");

		End = clock();
		printf("The time of differential attack is: %.0lf ms\n\n", double(End - Start));
	}goto start;
	case 4:
	{
		Start = clock();
		printf("The key is: \n");
		ViolentCrack(KeyTest);
		printf("\n");
		End = clock();
		printf("The time of differential decryption is: %.0lf ms\n\n", double(End - Start));
	}goto start;
	case 5:
    {
        Start=clock();
        printf("Begin to encrypt\n");
        FileEncryption(PlainFile, CipherFile, Key_plus);//加密函数
        printf("Finish to encrypt\n\n");

        End=clock();
        printf("The time of encrypting the file is: %.0lf ms\n\n",double(End-Start));
    }goto start;
    case 6:
    {
        Start=clock();

        FILE *fp;
        fp=fopen("spnKey_Plus.txt","w");
        char ch[]="0x3A,0x79,0x34,0x5D,0x16,0x33,0x9F,0x47,0x22,0x4E,0x54,0x92,0x61,0x1A,0x56,0x71,0x6B,0x2C,0x73,0x65,0x84,0x48,0x16,0x55,0xC4,0x61,0x87,0x99";

        fputs(ch,fp);
        fclose(fp);
        printf("Key to \"spnKey_Plus.txt\" successful.\n");
        FileDecryption(DecFile, CipherFile,Key_plus);//解密函数
        printf("Finish to decrypt\n\n");

        End=clock();
        printf("The time of decrypting the file is: %.0lf ms\n\n",double(End-Start));
    }goto start;
	default:
	{
		printf("Error!Input again!\n\n");
	}goto start;
	}
	system("Pause");
}
void SPN_Start(int* MesIn, int* MesOut, int K[])
{
	int i;
	static int Cup1[Len] = { 0 };
	static int Cup2[Len] = { 0 };
	Copy(MesIn, Cup1, Len);

	SPN_K(K);//处理轮密钥

	for (i = 0; i < 4; i++)
	{
		SPN_XOR(Cup1, Key[i]);   //白化
		bitToHex(Cup1, Cup2, Len);
		SPN_Change(Cup2, SBox);  //S盒代替
		hexToBit(Cup2, Cup1, Len);
		if (i != 3)
		{
			SPN_Trans(Cup1, Cup2, PBox);  //P盒置换
			Copy(Cup2, Cup1, Len);
		}
		else continue;
	}
	SPN_XOR(Cup1, Key[i]);       //白化
	Copy(Cup1, MesOut, Len);
}

void Copy(int* In, int* Out, int Length)
{
	int i = 0;
	for (; i < Length; i++)
		Out[i] = In[i];
}

void SPN_K(int K[])
{
	int i, j, z = 0;
	for (i = 0; i < 5; i++)
	{
		for (j = 0; j < Len; j++, z++)
			Key[i][j] = K[z];
		z = z - 12;
	}
}

void hexToBit(int* In, int* Out, int Length)
{
	int i;
	for (i = Length - 1; i >= 0; i--)
	{
		Out[i] = In[i / 4] % 2;
		In[i / 4] /= 2;
	}
}

void bitToHex(int* In, int* Out, int Length)
{
	int i;
	for (i = 0; i < Length / 4; i++)
		Out[i] = 8 * In[4 * i] + 4 * In[4 * i + 1] + 2 * In[4 * i + 2] + In[4 * i + 3];

}

void SPN_XOR(int* DataA, int* DataB)
//DataA同时为输出
{
	int i;
	for (i = 0; i < Len; i++)
		DataA[i] = DataA[i] ^ DataB[i];
}

void SPN_Change(int* Data, int* Change)
{
	int i = 0;
	for (; i < 4; i++)
		Data[i] = Change[Data[i]];
}

void SPN_Trans(int* In, int* Out, int* Change)
{
	int i;
	for (i = 0; i < Len; i++)
		Out[i] = In[Change[i] - 1];
}

void SPN_LineAttack(int* KeyOut, int Length)
{
	int L1, l1, L2, l2, z;
	int x, y, i;
	int Count[Len][Len];
	int RanIn[Len] = { 0 }, RanOut[Len] = { 0 };
	int U2[4] = { 0 }, U4[4] = { 0 };

	for (L1 = 0; L1 < Len; L1++)
		for (L2 = 0; L2 < Len; L2++)
			Count[L1][L2] = 0;

	for (i = 0; i < Length; i++)
	{
		RanText(RanIn, RanOut, K);
		for (L1 = 0; L1 < Len; L1++)
			for (L2 = 0; L2 < Len; L2++)
			{
				l1 = L1 ^ (RanOut[4] * 8 + RanOut[5] * 4 + RanOut[6] * 2 + RanOut[7]);
				l2 = L2 ^ (RanOut[12] * 8 + RanOut[13] * 4 + RanOut[14] * 2 + RanOut[15]);
				x = SBox_Opposite[l1];
				hexToBit(&x, U2, 4);
				y = SBox_Opposite[l2];
				hexToBit(&y, U4, 4);
				z = RanIn[4] ^ RanIn[6] ^ RanIn[7] ^ U2[1] ^ U2[3] ^ U4[1] ^ U4[3];
				if (z == 0)
					Count[L1][L2]++;
			}
	}
	int Max = -1;
	int Key1, Key2;
	for (L1 = 0; L1 < Len; L1++)
		for (L2 = 0; L2 < Len; L2++)
		{
			Count[L1][L2] = abs(Count[L1][L2] - Length / 2);
			if (Count[L1][L2] > Max)
			{
				Max = Count[L1][L2];
				Key1 = L1;
				Key2 = L2;
			}
		}
	hexToBit(&Key1, &KeyOut[20], 4);
	hexToBit(&Key2, &KeyOut[28], 4);
}

void SPN_DifAnalysis(int* KeyOut, int Length)
{
	int L1, l1, L2, l2;
	int i, j, m, y1_1, y3_1, y1_2, y3_2;

	int x[16] = { 0,0,0,0,1,0,1,1,0,0,0,0,0,0,0,0 };

	int Count[Len][Len];
	int RanIn1[Len] = { 0 }, RanIn2[Len] = { 0 };
	int RanOut1[Len] = { 0 }, RanOut2[Len] = { 0 };
	int U2_1, U4_1, U2_2, U4_2;

	for (L1 = 0; L1 < Len; L1++)
		for (L2 = 0; L2 < Len; L2++)
			Count[L1][L2] = 0;
	for (m = 0; m < Length; m++)
	{
		RanText(RanIn1, RanOut1, K);
		for (i = 0; i < Len; i++)
			RanIn2[i] = RanIn1[i] ^ x[i];
		SPN_Start(RanIn2, RanOut2, K);
		bitToHex(RanOut1, &y1_1, 4);
		bitToHex(&RanOut1[8], &y3_1, 4);
		bitToHex(RanOut2, &y1_2, 4);
		bitToHex(&RanOut2[8], &y3_2, 4);
		if (y1_1 == y1_2 && y3_1 == y3_2)
		{
			for (L1 = 0; L1 < Len; L1++)
				for (L2 = 0; L2 < Len; L2++)
				{
					l1 = L1 ^ (RanOut1[4] * 8 + RanOut1[5] * 4 + RanOut1[6] * 2 + RanOut1[7]);
					l2 = L2 ^ (RanOut1[12] * 8 + RanOut1[13] * 4 + RanOut1[14] * 2 + RanOut1[15]);
					U2_1 = SBox_Opposite[l1];
					U4_1 = SBox_Opposite[l2];
					l1 = L1 ^ (RanOut2[4] * 8 + RanOut2[5] * 4 + RanOut2[6] * 2 + RanOut2[7]);
					l2 = L2 ^ (RanOut2[12] * 8 + RanOut2[13] * 4 + RanOut2[14] * 2 + RanOut2[15]);
					U2_2 = SBox_Opposite[l1];
					U4_2 = SBox_Opposite[l2];
					i = U2_1 ^ U2_2;
					j = U4_1 ^ U4_2;
					if (i == 6 && j == 6)
						Count[L1][L2]++;
				}
		}
	}
	int Max = -1;
	int Key1, Key2;
	for (L1 = 0; L1 < Len; L1++)
		for (L2 = 0; L2 < Len; L2++)
			if (Count[L1][L2] > Max)
			{
				Max = Count[L1][L2];
				Key1 = L1;
				Key2 = L2;
			}
	hexToBit(&Key1, &KeyOut[20], 4);
	hexToBit(&Key2, &KeyOut[28], 4);

}

void RanText(int* In, int* Out, int Key[])
{
	int i, j;
	i = rand() % 65536;
	for (j = 15; j >= 0; j--)
	{
		In[j] = i % 2;
		i /= 2;
	}
	SPN_Start(In, Out, Key);
}

int MesOut1Sear[16] = { 0 }, MesOut2Sear[16] = { 0 };
int PlainSear[16] = { 0 };
bool flagSear = 0;

void searchOther(int m, int * &keyOut)
{
    int i, p, k;
    if(flagSear == 1) return;
    if(m == 28)
    {
        for (i = 0; i < 5; i++)
        {
            for (p = 0; p < 16; p++)
                PlainSear[p] = rand() % 2;
            SPN_Start(PlainSear, MesOut1Sear, K);
            SPN_Start(PlainSear, MesOut2Sear, keyOut);
            for (k = 0; k < 16; k++)
            {
                if (MesOut1Sear[k] != MesOut2Sear[k])
                {
                    flagSear = false;
                    break;
                }
            }
            if(k == 16) flagSear = true;
            if (!flagSear) break;
        }
    }
    else
    {
        for (i = 0; i < 2; i++)
        {
            if(flagSear == 1) return;
            keyOut[m] = i;
            if(m == 19) searchOther(24, keyOut);
            else searchOther(m + 1, keyOut);
        }
    }
    if(flagSear == 1) return;
}

void ViolentCrack(int* keyOut)
{
	SPN_DifAnalysis(keyOut, 300);
    searchOther(0, keyOut);
	for (int i = 0; i < 32; i++) printf("%d", keyOut[i]);
}

//*******************SPN_Plus******************//
//取文件大小
long filesize(FILE *fp)
{
    long save_pos;
    long size_of_file;
    save_pos=ftell(fp);//保存当前位置
    fseek(fp,0L,SEEK_END);//跳转至文件尾部
    size_of_file=ftell(fp);//取最后的位置
    fseek(fp,save_pos,SEEK_SET);//回到初始位置
    return(size_of_file);
}


void ENC(FILE *CipherFile, int *Key_plus)
{
    BYTE *CipherText;
    int CipherFileSize=filesize(CipherFile);
    CipherText=new BYTE[CipherFileSize];
    fseek(CipherFile,0,SEEK_SET);
    fread(CipherText,CipherFileSize,1,CipherFile);//将CipherFile中内容拷贝至CipherText中


	char inter_cipher[8];
    int i,j;
	//加密文件内容
    for (i=0;i<CipherFileSize;i+=8){
        for(j=0;j<8;j++)
            inter_cipher[j]=CipherText[i+j];

        BlockEncryption(inter_cipher,inter_cipher,Key_plus);

        for(j=0;j<8;j++)
            CipherText[i+j]=inter_cipher[j];
    }


    fseek(CipherFile,0,SEEK_SET);
    fwrite(CipherText,CipherFileSize,1,CipherFile);//将加密后得到的CipherText写入CipherText文件中
}

//文件加密
void FileEncryption(char* PlainFileName, char* CipherFileName, int* Key_plus)
{
    FILE *PlainFile=fopen(PlainFileName,"rb+");
    FILE *CipherFile=fopen(CipherFileName,"wb+");//源文件->加密文件CipherFile
    ciphertextinfo CipherTextInfo;
    CipherTextInfo.filename=PlainFileName;
    CipherTextInfo.w=strlen(PlainFileName);//w
    int CipherFileSize=filesize(PlainFile);
    CipherTextInfo.v=(CipherTextInfo.w+CipherFileSize)%2;//v
    BYTE* ComplementZero=NULL;
    ComplementZero=new BYTE[CipherTextInfo.v%2];
    if(CipherTextInfo.v==2) memset(ComplementZero,0,sizeof(ComplementZero));

    BYTE* PlainText=NULL;


    PlainText=new BYTE[CipherFileSize];

    fread(PlainText,CipherFileSize,1,PlainFile);
    printf("\nThe encrypted book is: %s\n\n",CipherTextInfo.filename);

	//按照要求的格式写入文件CipherText中
    fwrite(&CipherTextInfo.w,1,1,CipherFile);
    fwrite(CipherTextInfo.filename,strlen(CipherTextInfo.filename),1,CipherFile);
    fwrite(&CipherTextInfo.v,1,1,CipherFile);
    fwrite(PlainText,CipherFileSize,1,CipherFile);
    fwrite(ComplementZero,CipherTextInfo.v%2,1,CipherFile);

    //开始加密
    ENC(CipherFile,Key_plus);
    //结束 关闭文件
    fclose(PlainFile);
    fclose(CipherFile);
}

// 解密
void DEC(FILE* PlainFile, FILE* CipherFile, int* Key)
{
    BYTE* CipherText;
    int CipherFileSize = filesize(CipherFile);
    CipherText = new BYTE[CipherFileSize];
    fseek(CipherFile, 0, SEEK_SET);
    fread(CipherText, CipherFileSize, 1, CipherFile);
    char inter_plain[8];
    int i,j;
    for (i=0;i<CipherFileSize;i+=8){
        for(j=0;j<8;j++)
            inter_plain[j]=CipherText[i+j];

        BlockDecryption(inter_plain, inter_plain, Key);

        for(j=0;j<8;j++)
            CipherText[i+j]=inter_plain[j];
    }
    printf("\nThe encrypted book's size is: %d\n",&CipherFileSize);

    //解析 文件名 文件内容 ->解密后文件PlainFile中
    ciphertextinfo PlainFileInfo;
    PlainFileInfo.w=CipherText[0];
    PlainFileInfo.filename=new char[PlainFileInfo.w];

    for (i=0;i<PlainFileInfo.w;i++)
        PlainFileInfo.filename[i]=CipherText[i+1];
    PlainFileInfo.v=CipherText[1+PlainFileInfo.w];
    BYTE *PlainText=NULL;
    int PlainTextLength=CipherFileSize-2-PlainFileInfo.w-PlainFileInfo.v;

    //cout<<"文件内容长度:"<<PlainTextLength<<endl;
    PlainText = new BYTE[PlainTextLength];
    for (i=0;i<PlainTextLength;i++)
        PlainText[i]=CipherText[i+2+PlainFileInfo.w];
    //cout<<"文件内容:"<<PlainText<<endl;
    fseek(PlainFile,0,SEEK_SET);
    fwrite(PlainText,PlainTextLength,1,PlainFile);
}

//文件解密
void FileDecryption(char *PlainFileName, char *CipherFileName, int *Key)
{
    FILE *PlainFile=fopen(PlainFileName,"wb+");//读到解密文件 PlainFile中
    FILE *CipherFile=fopen(CipherFileName,"rb+");
    DEC(PlainFile,CipherFile,Key);
    fclose(PlainFile);
    fclose(CipherFile);
}



void BlockEncryption(char* PlainText, char* CipherText, int* Key_plus)
{

    int K_plus[12][8];
    int r=12;
	int i,j,k;
    for(i=0;i<r;i++){
        for(j=0;j<8;j++){
            K_plus[i][j] = Key_plus[i+j];
        }
    }
    int w[8],u[8],v[8];

    for(i=0;i<8;i++) w[i]=PlainText[i]&0xff;

    for(i=0;i<r-1;i++){
        for(j=0;j<8;j++)
            u[j]=w[j]^K_plus[i][j];

        for(j=0;j<8;j++)
            v[j]=SBox_Plus[u[j]];

        int w_t[64];

        for(j=0;j<64;j++)
            w_t[j]=v[j/8]>>(7-j%8)&1;

        for(j=0;j<8;j++){
            w[j]=0;
            for (k=0;k<8;k++)
                w[j]+=w_t[PBox_Plus[j*8+k]]<<(7-k);
        }
    }
    for(i=0;i<8;i++)
        CipherText[i]=(v[i]^K_plus[11][i])&0xff;//最后一轮 得到加密后的密文

}

void BlockDecryption(char *PlainText,char *CipherText,int *Key_plus)
{

    int K_plus[12][8];
    int r = 12;
	int i,j,k;
    for (i=0;i<r;i++) {
        for (j=0;j<8;j++) {
            K_plus[i][j] = Key_plus[i+j];
        }
    }
    int w[8],u[8],v[8];
    for(i=0;i<8;i++)
        v[i]=(CipherText[i]^K_plus[11][i])&0xff;

    for (i=r-2;i>=0;i--){
        for(j=0;j<8;j++) u[j]=SBox_Plus_Opposite[v[j]];
        for(j=0;j<8;j++) w[j]=u[j]^K_plus[i][j];
        int v_t[64];
        for(j=0;j<64; j++) v_t[j]=w[j/8]>>(7-j%8)&1;
        for(j=0;j<8;j++){
            v[j]=0;
            for(k=0;k<8;k++)
                v[j]+=v_t[PBox_Plus_Opposite[j*8+k]]<<(7-k);
        }
    }
    for(i=0;i<8;i++)
        PlainText[i]=(w[i])&0xff;
}