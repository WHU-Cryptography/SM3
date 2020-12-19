
#define SM3_HASH_SIZE 32
namespace SM3 {
	/*哈希值向量大小，单位为字节*/
	typedef struct SM3Context {
		unsigned int intermediateHash[SM3_HASH_SIZE / 4];
		unsigned char messageBlock[64];//512位的数据块，是迭代压缩的对象
	} SM3Context;

	unsigned char *SM3Calc(const unsigned char *message,
		unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);

	std::vector<uint32_t> call_hash_sm3(char *filepath);

	double progress();
}