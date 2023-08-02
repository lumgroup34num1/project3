# project3 length extension attack for SM3
## 1、实验原理
SM3的消息长度是64字节或者它的倍数，如果消息的长度不足则需要padding填充。  padding填充规则，首先填充一个1，随后填充0，直到消息长度为56(或者再加整数倍的64)字节，最后8字节用来填充消息的长度。  
在SM3函数计算时，首先对消息进行分组，每组64字节，每一次加密一组，并更新8个初始向量(初始值已经确定)，下一次用新向量去加密下一组，以此类推。我们可以利用这一特性去实现攻击。当我们得到第一次加密后的向量值时，再人为构造一组消息用于下一次加密，就可以在不知道secret的情况下得到合法的hash值，这是因为8个向量中的值便能表示第一轮的加密结果。
## 2、代码实现
```
uint32_t Padding_extend_attack(vector<bool>* input, uint32_t* M, uint64_t len)
{
	uint64_t size = (*input).size();
	uint32_t pad_size = (447 - size + 512) % 512, temp;
	size = size + 1 + (uint64_t)pad_size;
	(*input).push_back(1);											
	(*input).resize(size, 0);
	for (uint32_t i = 0; i < size; i += 32)
	{
		temp = 0;
		for (uint32_t j = 0; j < 31; ++j)
		{
			temp |= (*input)[i + j]; temp <<= 1;
		}
		temp |= (*input)[i + 31];
		M[(uint32_t)(i / 32)] = temp;
	}
	M[(uint32_t)(size / 32)] = (uint32_t)(len >> 32);							
	M[(uint32_t)(size / 32 + 1)] = ((uint32_t)len);
	return (uint32_t)((size / 32 + 2) / 16);
}
```
## 3、实验结果
![image](https://github.com/lumgroup34num1/project3/assets/129478488/691de1df-2f44-46f0-a029-c93163118d0e)
