#include <string.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <iomanip>
#include <memory>
#include "SM3.h"
#define MAXSIZE 1024*1024*2//假设加密文件最大为2KB
//using namespace SM3;
unsigned int hash_all = 0;//总的消息块
unsigned int hash_rate = 0;//当前hash进度
/*判断运行环境是否为小端*/
static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)
/*向左循环移位*/
#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) )
/* 反转四字节整型字节序*/
unsigned int *ReverseWord(unsigned int *word)
{
	unsigned char *byte, temp;

	byte = (unsigned char *)word;
	temp = byte[0];
	byte[0] = byte[3];
	byte[3] = temp;

	temp = byte[1];
	byte[1] = byte[2];
	byte[2] = temp;
	return word;

}
/*T*/
unsigned int T(int i)
{
	if (i >= 0 && i <= 15)
		return 0x79CC4519;
	else if (i >= 16 && i <= 63)
		return 0x7A879D8A;
	else
		return 0;
}

/*FF*/
unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (X & Z) | (Y & Z);
	else
		return 0;
}

/*GG*/
unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (~X & Z);
	else
		return 0;
}

/*P0*/
unsigned int P0(unsigned int X)
{
	return X ^ LeftRotate(X, 9) ^ LeftRotate(X, 17);
}

/*P1*/
unsigned int P1(unsigned int X)
{
	return X ^ LeftRotate(X, 15) ^ LeftRotate(X, 23);
}

/*初始化函数*/
void SM3Init(SM3::SM3Context *context) {
	context->intermediateHash[0] = 0x7380166F;
	context->intermediateHash[1] = 0x4914B2B9;
	context->intermediateHash[2] = 0x172442D7;
	context->intermediateHash[3] = 0xDA8A0600;
	context->intermediateHash[4] = 0xA96F30BC;
	context->intermediateHash[5] = 0x163138AA;
	context->intermediateHash[6] = 0xE38DEE4D;
	context->intermediateHash[7] = 0xB0FB0E4E;
}

/* 处理消息块*/
void SM3ProcessMessageBlock(SM3::SM3Context *context)
{
	int i;
	unsigned int W[68];
	unsigned int W_[64];
	unsigned int A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;

	/* 消息扩展 */
	for (i = 0; i < 16; i++)
	{
		W[i] = *(unsigned int *)(context->messageBlock + i * 4);
		if (IsLittleEndian())
			ReverseWord(W + i);
		//        printf("%d: %x\n", i, W[i]);
	}
	for (i = 16; i < 68; i++)
	{
		W[i] = P1(W[i - 16] ^ W[i - 9] ^ LeftRotate(W[i - 3], 15))
			^ LeftRotate(W[i - 13], 7)
			^ W[i - 6];
		//        printf("%d: %x\n", i, W[i]);
	}
	for (i = 0; i < 64; i++)
	{
		W_[i] = W[i] ^ W[i + 4];
		//        printf("%d: %x\n", i, W_[i]);
	}

	/* 消息压缩 */
	A = context->intermediateHash[0];
	B = context->intermediateHash[1];
	C = context->intermediateHash[2];
	D = context->intermediateHash[3];
	E = context->intermediateHash[4];
	F = context->intermediateHash[5];
	G = context->intermediateHash[6];
	H = context->intermediateHash[7];
	for (i = 0; i < 64; i++)
	{
		//        printf("%d: %x\n", i, A);
		//        printf("%d: %x\n", i, B);
		//        printf("%d: %x\n", i, C);
		//        printf("%d: %x\n", i, D);
		//        printf("%d: %x\n", i, E);
		//        printf("%d: %x\n", i, F);
		//        printf("%d: %x\n", i, G);
		//        printf("%d: %x\n", i, H);
		unsigned int SS3;
		//        SS3 = LeftRotate(A, 12);
		//        printf("SS3: %d: %x\n", i, SS1);

		SS1 = LeftRotate((LeftRotate(A, 12) + E + LeftRotate(T(i), i)), 7);
		SS2 = SS1 ^ LeftRotate(A, 12);
		TT1 = FF(A, B, C, i) + D + SS2 + W_[i];
		TT2 = GG(E, F, G, i) + H + SS1 + W[i];


		//        printf("SS1: %d: %x\n", i, SS1);
		//        printf("SS2: %d: %x\n", i, SS2);
		//        printf("TT1: %d: %x\n", i, TT1);
		//        printf("TT2: %d: %x\n", i, TT2);

		D = C;
		C = LeftRotate(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = LeftRotate(F, 19);
		F = E;
		E = P0(TT2);
	}
	context->intermediateHash[0] ^= A;
	context->intermediateHash[1] ^= B;
	context->intermediateHash[2] ^= C;
	context->intermediateHash[3] ^= D;
	context->intermediateHash[4] ^= E;
	context->intermediateHash[5] ^= F;
	context->intermediateHash[6] ^= G;
	context->intermediateHash[7] ^= H;
}

/*
* SM3算法主函数:
	message代表需要加密的消息字节串;
	messagelen是消息的字节数;
	digset表示返回的哈希值
*/
unsigned char *SM3::SM3Calc(const unsigned char *message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE])
{
	SM3::SM3Context context;
	unsigned int i, remainder, bitLen;

	/* 初始化上下文 */
	SM3Init(&context);
	hash_all = messageLen / 64 + 1;//计算总块数
	remainder = messageLen % 64;
	if (remainder > 55){
		hash_all += 1;//总块数还要+1
	}
	/* 对前面的消息分组进行处理 */
	for (i = 0; i < messageLen / 64; i++)
	{
		memcpy(context.messageBlock, message + i * 64, 64);
		hash_rate = i + 1;//每处理一个512bit的消息块，进度就+1
		SM3ProcessMessageBlock(&context);
	}

	/* 填充消息分组，并处理 */
	bitLen = messageLen * 8;
	if (IsLittleEndian())
		ReverseWord(&bitLen);
	memcpy(context.messageBlock, message + i * 64, remainder);
	context.messageBlock[remainder] = 0x80;//添加bit‘0x1000 0000’到末尾
	if (remainder <= 55)//如果剩下的bit数少于440
	{
		/* 长度按照大端法占8个字节，只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		hash_rate += 1;//计算最后一个短块
		SM3ProcessMessageBlock(&context);
	}
	else
	{
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1);
		hash_rate += 1;//计算短块
		SM3ProcessMessageBlock(&context);
		/* 长度按照大端法占8个字节，只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset(context.messageBlock, 0, 64 - 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		hash_rate += 1;//计算最后一个短块
		SM3ProcessMessageBlock(&context);
	}

	/* 返回结果 */
	if (IsLittleEndian())
		for (i = 0; i < 8; i++)
			ReverseWord(context.intermediateHash + i);
	memcpy(digest, context.intermediateHash, SM3_HASH_SIZE);

	return digest;
}

/*
* call_hash_sm3函数
	输入参数：文件地址字符串
	输出：向量vector<unit32_t> hash_result(32)
*/
std::vector<uint32_t> SM3::call_hash_sm3(char *filepath)
{
	std::vector<uint32_t> hash_result(32, 0);
	std::ifstream infile;
	uint32_t FILESIZE = 0;
	unsigned char * buffer = new unsigned char[MAXSIZE];
	unsigned char hash_output[32];
	/*获取文件大小*/
	struct _stat info;
	_stat(filepath, &info);
	FILESIZE = info.st_size;
	/*打开文件*/
	infile.open(filepath, std::ifstream::binary);
	infile >> buffer;
	/*	printf("Message:\n");
		printf("%s\n", buffer);
	*/
	SM3::SM3Calc(buffer, FILESIZE, hash_output);
	/*	printf("Hash:\n   ");
		for (int i = 0; i < 32; i++)
		{
			printf("%02x", hash_output[i]);
			if (((i + 1) % 4) == 0) printf(" ");
		}
		printf("\n");
	*/
	hash_result.assign(&hash_output[0], &hash_output[32]);
	/*	for (int i = 0; i < 32; i++) {
			std::cout <<std::hex << std::setw(2) << std::setfill('0') << hash_result[i];
			if (((i + 1) % 4) == 0) std::cout <<" ";
		}
		std::cout << std::endl;
	*/
	delete[]buffer;
	return hash_result;
}

/*计算当前哈希进度*/
double progress() {
	return (double(hash_rate) / hash_all);
}

/*测试函数，整合后可以注释掉*/
int main() {
	char filepath[] = "test.txt";
	std::vector<uint32_t> hash_result;
	hash_result = SM3::call_hash_sm3(filepath);
	for (int i = 0; i < 32; i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << hash_result[i];
		if (((i + 1) % 4) == 0) std::cout << " ";
	}
	std::cout << std::endl;

	double rate = progress();
	printf("\n当前进度: %f", rate);
	return 0;
}
