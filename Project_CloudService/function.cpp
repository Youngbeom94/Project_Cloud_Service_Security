#include "header.h"


void Print_char(char* src, int len)
{
	for (int cnt_i = 0; cnt_i < len; cnt_i++)
	{
		printf("%02X ", (unsigned char)src[cnt_i]);
	}
	printf("\n");
	return;
}

void Copy_char(char* dst, char* src, int len)
{
	for (int cnt_i = 0; cnt_i < len; cnt_i++)
	{
		dst[cnt_i] = src[cnt_i];
	}
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

void Generating_key_using_fixed_digest(char* src, int src_len, char* digest)
{
	int cnt_i = 0;

	for (cnt_i = 0; cnt_i < src_len; cnt_i++)
	{
		src[cnt_i] = digest[cnt_i];
	}
}

void XOR_two_char_using_CBC(char* src, char* dst, int len)
{
	int cnt_i = 0;
	for (cnt_i = 0; cnt_i < len; cnt_i++)
	{
		dst[cnt_i] ^= src[cnt_i];
	}
}
void Client_Encrypte_File(char* dst, char* src, char* key,int len, int Crypto_Flag)
{
	switch (Crypto_Flag)
	{
	case AES:
		Client_Encryption_using_AES_128_CBC(src, len, dst, key);
		printf("Client Choose AES-128bit block cipher to encrypt\n");
		break;

	case LEA:
		break;

	case SEED:
		break;

	default:
		printf("Encrypt File Error\n");
	}
}

void Client_Encrypte_C_to_LC(char* dst, char* src, char* key, int len, int Crypto_Flag)
{
	switch (Crypto_Flag)
	{
	case AES:
		Client_Encryption_LC_using_AES_128_CBC(src, len, dst, key);
		printf("Client Choose AES-128bit block cipher to encrypt\n");
		break;

	case LEA:
		break;

	case SEED:
		break;

	case XOR_based:
		break;

	default:
		printf("Encrypt File Error\n");
	}
}

void Client_Hashing_File(char* dst, char* src, int len,int Hashing_Flag)
{
	switch (Hashing_Flag)
	{
	case SHA_256:
		Hash_Function_using_SHA_256(src, len, dst);
		printf("Client Choose SHA-256 to Hashing\n");
		break;

	case SHA_512:
		break;

	case SHA_3:
		break;

	default:
		printf("Encrypt File Error\n");
	}
}

void Server_Hashing_File_to_Tag(char* dst, char* src, int len, int Hashing_Flag)
{
	switch (Hashing_Flag)
	{
	case SHA_256:
		Hash_Function_using_SHA_256(src, len, dst);
		break;

	case SHA_512:
		break;

	case SHA_3:
		break;

	default:
		printf("Encrypt File Error\n");
	}
}

void Server_Decrypt_LC_to_C(char* dst, char* src, char* key, int len, int Crypto_Flag)
{
	switch (Crypto_Flag)
	{
	case AES:
		Server_LC_Decryption_using_AES_128_CBC(src, len,dst, key);
		break;

	case LEA:
		break;

	case SEED:
		break;

	case XOR_based:
		break;

	default:
		printf("Encrypt File Error\n");
	}

}
void Client_Encryption_using_AES_128_CBC(char* src, int src_len, char* dst, char* key)
{
	int cnt_i = 0, cnt_j = 0;
	char buff[16] = { 0x00 };
	//char IV_vector_CBC[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	char IV_vector_CBC[16] = { 0x00, };
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
				dst[(cnt_i * 16) + cnt_j] = buff[cnt_j];
			}
		}
		else
		{
			aes_encrypt(pt_a, buff);
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				dst[(cnt_i * 16) + cnt_j] = buff[cnt_j];
			}
		}
	}
	//! AES decrypt
	//aes_decrypt(pt_a, buff);
	aes_end(pt_a);

}

void Client_Encryption_LC_using_AES_128_CBC(char* src, int src_len, char* dst, char* key)
{
	int cnt_i = 0, cnt_j = 0;
	char buff[16] = { 0x00 };
	//char IV_vector_CBC[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	char IV_vector_CBC[16] = { 0x00, };
	char Padding_src[CLIENT_FILE_LEN_PADDING] = { 0x00 };

	for (cnt_i = 0; cnt_i < CLIENT_FILE_LEN_PADDING; cnt_i++)
	{
		Padding_src[cnt_i] = src[cnt_i];
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
				dst[(cnt_i * 16) + cnt_j] = buff[cnt_j];
			}
		}
		else
		{
			aes_encrypt(pt_a, buff);
			for (cnt_j = 0; cnt_j < 16; cnt_j++)
			{
				dst[(cnt_i * 16) + cnt_j] = buff[cnt_j];
			}
		}
	}
	//! AES decrypt
	//aes_decrypt(pt_a, buff);
	aes_end(pt_a);

}

void Client_Check_TagC_in_DB(_CLIENT_* Client, _SERVER_* Server)
{
	int cnt_i = 0x00, cnt_j = 0x00;

	for (cnt_i = 0; cnt_i < DB_Range; cnt_i++)
	{
		for (cnt_j = 0; cnt_j < HASH_DIGEST_BYTE; cnt_j++)
		{
			if (Client->Client_Tag[cnt_j] != Server->DB_TagC[cnt_i][cnt_j])
			{
				break;
			}
			if (cnt_j == (HASH_DIGEST_BYTE - 1))
			{
				Client->DB_Flag = TRUE;
				printf("Client_TagC in DB of SerVer\n\n");
				Server_add_Client_to_UIDC(Server->DB_UIDC, Client->name, &((Server)->Client_Numeber));
				return;
			}
		}
	}
	Client->DB_Flag = FALSE;
	Server->Client_Numeber = 0;
	printf("Client receive N/A of TagC from Server\n\n");

}



void Server_LC_Decryption_using_AES_128_CBC(char* src, int src_len, char* dst, char* key)
{
	int cnt_i = 0, cnt_j = 0;
	char buff[(CLIENT_FILE_LEN_PADDING / 16)][16] = { {0x00}, };
	//char IV_vector_CBC[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	char IV_vector_CBC[16] = { 0x00, };
	char Padding_src[CLIENT_FILE_LEN_PADDING] = { 0x00 };

	aes a_1 = { {0x00}, };
	aes* pt_a = &a_1;

	//! AES init
	aes_init(pt_a, MR_ECB, 16, key, NULL);

	//! AES decrypt
	for (cnt_i = 0; cnt_i < (CLIENT_FILE_LEN_PADDING / 16); cnt_i++)
	{
		for (cnt_j = 0; cnt_j < PT_LEN; cnt_j++)
		{
			buff[cnt_i][cnt_j] = src[(cnt_i * PT_LEN) + cnt_j];
		}
		aes_decrypt(pt_a, buff[cnt_i]);
	}

	//! AES decrypt
	for (cnt_i = (CLIENT_FILE_LEN_PADDING / 16); cnt_i > 0; cnt_i--) //2
	{
		if (cnt_i == 1)
		{
			XOR_two_char_using_CBC(IV_vector_CBC, buff[0], PT_LEN);
			break;
		}
		XOR_two_char_using_CBC(&src[(cnt_i - 2) * PT_LEN], buff[cnt_i - 1], PT_LEN);

	}

	for (cnt_i = 0; cnt_i < (CLIENT_FILE_LEN_PADDING / 16); cnt_i++)
	{
		for (cnt_j = 0; cnt_j < PT_LEN; cnt_j++)
		{
			dst[(cnt_i * PT_LEN) + cnt_j] = buff[cnt_i][cnt_j];
		}
	}

	aes_end(pt_a);
}

void Server_add_Client_to_UIDC(char DB_UIDC[DB_Range][HASH_DIGEST_BYTE], char* Client_Name, char* Clt_num)
{
	int cnt_i, cnt_j = 0;
	int temp = 0;
	sha256 psh = { {0x00}, };
	sha256* pt_psh = &psh;


	//! SHA init
	shs256_init(pt_psh);

	for (cnt_i = 0; cnt_i < Client_Name_Len; cnt_i++)
	{
		shs256_process(pt_psh, Client_Name[cnt_i]);
	}

	for (cnt_i = 0; cnt_i < Client_Name_Len; cnt_i++)
	{
		for (cnt_j = 0; cnt_j < HASH_DIGEST_BYTE; cnt_j++)
		{
			if (DB_UIDC[cnt_i][cnt_j] != 0x00)
			{
				break;
			}
			temp = cnt_i;
			break;
		}
	}
	shs256_hash(pt_psh, DB_UIDC[temp]);
	*Clt_num = temp;

}

void Server_Tag_Verification(char* src1, char* src2, int len, char* tag_flag)
{
	int cnt_i = 0x00;

	for (cnt_i = 0; cnt_i < len; cnt_i++)
	{
		if (src1[cnt_i] != src2[cnt_i])
		{
			*tag_flag = FALSE;
			continue;
		}

	}
	if (*tag_flag == FALSE)
	{
		printf("------Server Tag Verification Fail------\n\n");
		return;
	}

	*tag_flag = TRUE;
	printf("------Server Tag Verification Success------\n\n");

}

void Client_Read_File(_CLIENT_* Client)
{
	char from_a_txt[CLIENT_FILE_LEN];
	FILE* file_pointer;
	file_pointer = fopen("Client_Pt.txt", "r");
	fgets(from_a_txt, CLIENT_FILE_LEN, file_pointer);

	//printf("Current File data: %s \n", from_a_txt);

	Copy_char(Client->Pt_Client_File, from_a_txt, CLIENT_FILE_LEN);

	fclose(file_pointer);


}

void Server_Write_File(_SERVER_* Server)
{
	int cnt_i = 0;
	FILE* file_pointer;
	file_pointer = fopen("Server_DB.txt", "w");
	fputs("[********SERVER DB********]\n", file_pointer);

	fputs("[UIDC]\n", file_pointer);
	for (cnt_i = 0; cnt_i < HASH_DIGEST_BYTE; cnt_i++)
	{
		fprintf(file_pointer, "%02X ", (unsigned char)Server->DB_UIDC[Server->Client_Numeber][cnt_i]);
	}

	fputs("\n[TagC]\n", file_pointer);
	for (cnt_i = 0; cnt_i < HASH_DIGEST_BYTE; cnt_i++)
	{
		fprintf(file_pointer, "%02X ", (unsigned char)Server->DB_TagC[Server->Client_Numeber][cnt_i]);
	}

	fputs("\n[Encrypted Client File]\n", file_pointer);
	for (cnt_i = 0; cnt_i < CLIENT_FILE_LEN_PADDING; cnt_i++)
	{
		fprintf(file_pointer, "%02X ", (unsigned char)Server->DB_Ct_Client_File[cnt_i]);
	}

	fclose(file_pointer);

}

int	char_compare(char* src1, char* src2, int len)
{
	int cnt_i = 0;

	for (cnt_i = 0; cnt_i < len; cnt_i++)
	{
		if (src1[cnt_i] != src2[cnt_i])
		{
			return FALSE;
		}
	}

	return TRUE;
}