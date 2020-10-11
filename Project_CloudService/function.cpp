#include "header.h"

void Print_char(char* src, int len)
{
	for (int cnt_i = 0; cnt_i < len; cnt_i++)
	{
		printf("0x%02X ", (unsigned char)src[cnt_i]);
	}
	printf("\n");
	return;
}


void Hash_Function_using_SHA_256(char* src, int src_len, char* digest)
{
	int cnt_i;
	sha256 psh = { {0x00}, };
	sha256* pt_psh = &psh;
	//! SHA init
	shs256_init(pt_psh);

	for (cnt_i = 0; cnt_i < src_len; cnt_i++)
	{
		shs256_process(pt_psh, src[cnt_i]);
	}
	shs256_hash(pt_psh, digest);

	//char test[] = "Crypto Optimization and Application Lab Avengers"; 
}

void Generating_key_using_256_digest(char* src, int src_len, char* digest)
{
	int cnt_i = 0;

	for (cnt_i = 0; cnt_i < src_len; cnt_i++)
	{
		src[cnt_i] = digest[cnt_i];
	}
}

void XOR_two_char_using_CBC(char* src, char* drc,int len)
{
	int cnt_i = 0;
	for (cnt_i = 0; cnt_i < len; cnt_i++)
	{
		drc[cnt_i] ^= src[cnt_i];
	}
}

void Client_Encryption_using_AES_128_CBC(char*src, int src_len ,char*drc, char*key) 
{
	int cnt_i=0, cnt_j = 0;
	char buff[16] = {0x00};
	//char IV_vector_CBC[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	char IV_vector_CBC[16] = { 0x00,};
	char Padding_src[CLIENT_FILE_LEN_PADDING] = { 0x00 };

	for (cnt_i = 0; cnt_i < CLIENT_FILE_LEN_PADDING; cnt_i++)
	{
		if (cnt_i < CLIENT_FILE_LEN)
		{
			Padding_src[cnt_i] = src[cnt_i];
		}
		else
		{
			Padding_src[cnt_i] = 0x00;
		}
	}

	aes a_1 = { {0x00}, };
	aes* pt_a = &a_1;

	
	//! AES init
	aes_init(pt_a, MR_ECB, 16, key, NULL);

	//! AES encrypt
	for (cnt_i = 0; cnt_i < (CLIENT_FILE_LEN_PADDING / 16); cnt_i++)
	{
		for (cnt_j = 0; cnt_j < 16; cnt_j++)
		{
			buff[cnt_j] ^= Padding_src[(cnt_i * 16) + cnt_j];

		}
		
		if (cnt_i == 0)
		{
			XOR_two_char_using_CBC(buff, IV_vector_CBC, 16);
			aes_encrypt(pt_a, buff);
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				drc[(cnt_i * 16) + cnt_j] = buff[cnt_j];
			}

		}
		else
		{
			aes_encrypt(pt_a, buff);
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				drc[(cnt_i * 16) + cnt_j] = buff[cnt_j];
			}
		}
		
	}

	//! AES decrypt
	//aes_decrypt(pt_a, buff);

	aes_end(pt_a);
}
