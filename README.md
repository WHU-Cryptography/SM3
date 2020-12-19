# SM3
实现了SM3的哈希算法
调用SM3::call_hash_sm3(char *stirng)函数，传入文件名地址字符串即可得到一个vector<uint32_t> hash_result(32)的向量结果，向量中每个32bit元素含有8bit的哈希值
调用SM3::progress()函数，会返回一个double型的进度值。
