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

void Hash_MAC(char* src, int src_len, char* key, int key_len, char* mac)
{
	int cnt_i = 0x00;
	char* K1 = NULL;
	char* K2 = NULL;
	char digest[HASH_DIGEST_BYTE] = { 0x00 };

	K1 = (char*)calloc(key_len + src_len, sizeof(char));
	K2 = (char*)calloc(key_len + HASH_DIGEST_BYTE, sizeof(char));

	for (cnt_i = 0; cnt_i < key_len; cnt_i++)
	{
		K1[cnt_i] = key[cnt_i] ^ IPAD;
		K2[cnt_i] = key[cnt_i] ^ OPAD;
	}
	for (cnt_i = key_len; cnt_i < key_len + src_len; cnt_i++)
	{
		K1[cnt_i] = src[cnt_i - key_len];
	}

	Hash_Function_using_SHA_256(K1, key_len + src_len, digest);

	for (cnt_i = key_len; cnt_i < key_len + HASH_DIGEST_BYTE; cnt_i++)
	{
		K2[cnt_i] = digest[cnt_i - key_len];
	}

	Hash_Function_using_SHA_256(K2, key_len + HASH_DIGEST_BYTE, mac);

	free(K1);
	free(K2);
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
void Client_Encrypte_File(char* dst, char* src, char* key, int len, int Crypto_Flag)
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

void Client_Hashing_File(char* dst, char* src, int len, int Hashing_Flag)
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
		Hash_Function_using_SHA_256(src, len, dst);
		break;
	}
}

void Server_Decrypt_LC_to_C(char* dst, char* src, char* key, int len, int Crypto_Flag)
{
	switch (Crypto_Flag)
	{
	case AES:
		Server_LC_Decryption_using_AES_128_CBC(src, len, dst, key);
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

void Client_Check_TagC_in_DB(_CLIENT_* Client, _SERVER_* Server, int* current_client)
{
	int cnt_i = 0x00, cnt_j = 0x00, cnt_k = 0x00;
	FILE* file_pointer;

	for (cnt_i = 0; cnt_i < MAX_DB; cnt_i++)
	{
		for (cnt_j = 0; cnt_j < HASH_DIGEST_BYTE; cnt_j++)
		{
			if (Client[*current_client].File[Client[*current_client].current_file].Client_Tag[cnt_j] != Server->DB[cnt_i].DB_TagC[cnt_j])
			{
				break;
			}

			if (cnt_j == (HASH_DIGEST_BYTE - 1))
			{
				printf("Client_TagC in DB of SerVer\n");
				printf("Start proof of ownership process\n");
				big random = mirvar(0);
				char key[HASH_DIGEST_BYTE] = { 0x00 };
				char Client_result[HASH_DIGEST_BYTE] = { 0x00 };
				char Server_result[HASH_DIGEST_BYTE] = { 0x00 };
				bigbits(256, random);
				big_to_bytes(HASH_DIGEST_BYTE, random, key, TRUE);

				Hash_MAC(Client[*current_client].File[Client[*current_client].current_file].Ct_Client_File, CLIENT_FILE_LEN_PADDING, key, HASH_DIGEST_BYTE, Client_result);
				Hash_MAC(Server->DB[cnt_i].DB_Ct_Client_File, CLIENT_FILE_LEN_PADDING, key, HASH_DIGEST_BYTE, Server_result);

				for (cnt_k = 0; cnt_k < HASH_DIGEST_BYTE; cnt_k++)
				{
					if (Client_result[cnt_k] != Server_result[cnt_k])
					{
						Server->DB_Flag = BAD;
						printf("Proof of ownership Fail\n");
						return;
					}
				}
				if (Server->test_Flag == FALSE)
				{
					Server->DB_Flag = BAD;
					printf("Proof of ownership Fail\n");
					Server->test_Flag = TRUE;
					return;
				}

				printf("Proof of ownership Complete\n");
				Hash_Function_using_SHA_256(Client[*current_client].name, Client_Name_Len, Server->DB[cnt_i].DB_UIDC[Server->DB[cnt_i].UIDC_NUM]);
				Server->DB[cnt_i].UIDC_NUM = Server->DB[cnt_i].UIDC_NUM + 1;
				Server->DB_Flag = TRUE;;
				return;
			}
		}
	}
	Server->DB_Flag = FALSE;
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

void Server_add_Client_to_UIDC(char* dst, char* src)
{
	int cnt_i, cnt_j = 0;
	int temp = 0;
	sha256 psh = { {0x00}, };
	sha256* pt_psh = &psh;

	//! SHA init
	shs256_init(pt_psh);

	for (cnt_i = 0; cnt_i < Client_Name_Len; cnt_i++)
	{
		shs256_process(pt_psh, src[cnt_i]);
	}

	shs256_hash(pt_psh, dst);
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

void Client_Read_File(_CLIENT_* Client, int* current_client)
{
	int temp;
	FILE* file_pointer;
	char User_name[Client_Name_Len];
	char fileName[FILENAME_LEN];
	char from_a_txt[CLIENT_FILE_LEN];

	printf("Please Enter User Name : ");
	scanf_s("%s", User_name, sizeof(User_name));
	Add_File_Client_Num(Client, User_name, current_client);

	system("dir");
	temp = getchar();

	printf("Please Enter File Name : ");
	fgets(fileName, sizeof(fileName), stdin);

	file_pointer = fopen(fileName, "r");
	assert(file_pointer != NULL);


	fgets(from_a_txt, CLIENT_FILE_LEN, file_pointer);

	Client[*current_client].current_file++;
	Copy_char(Client[*current_client].File[Client[*current_client].current_file].file_name, fileName, FILENAME_LEN);
	Copy_char(Client[*current_client].File[Client[*current_client].current_file].Pt_Client_File, from_a_txt, CLIENT_FILE_LEN);

	//printf("current_user %d\n", *current_client);
	//printf("current_File name \n");
	//Print_char(Client[*current_client].File[Client[*current_client].current_file].file_name, FILENAME_LEN);
	//printf("current_File %d\n", Client[*current_client].current_file);
	//printf("current_File data \n");
	//Print_char(Client[*current_client].File[Client[*current_client].current_file].Pt_Client_File, CLIENT_FILE_LEN);

	fclose(file_pointer);
}

void Add_File_Client_Num(_CLIENT_* Client, char* name, int* current_client)
{
	int cnt_i = 0x00, cnt_j = 0x00, cnt_k = 0x00;
	//Print_char(name, Client_Name_Len);
	for (cnt_i = 0; cnt_i < MAX_CLIENT; cnt_i++)
	{
		for (cnt_j = 0; cnt_j < Client_Name_Len; cnt_j++)
		{
			if (Client[cnt_i].name[cnt_j] != name[cnt_j])
			{
				break;
			}

			if (cnt_j == (Client_Name_Len - 1))
			{
				*current_client = cnt_i;
				printf("Client aleady Access\n");
				return;
			}
		}
	}

	*current_client = *current_client + 1;
	for (cnt_i = 0; cnt_i < Client_Name_Len; cnt_i++)
	{
		Client[*current_client].name[cnt_i] = name[cnt_i];
	}
	return;
}

void Server_Write_File(_SERVER_* Server)
{
	int cnt_i, cnt_j,cnt_k = 0;
	FILE* file_pointer;
	file_pointer = fopen("Server_DB.txt", "w");

	for (cnt_i = 0; cnt_i < Server->range_DB; cnt_i++)
	{
		fprintf(file_pointer, "\n[File : %s]\n", Server->DB[cnt_i].DB_file_name);

		fputs("---UIDC---\n", file_pointer);
		for (cnt_j = 0; cnt_j < Server->DB[cnt_i].UIDC_NUM ; cnt_j++)
		{
			for (cnt_k = 0; cnt_k < HASH_DIGEST_BYTE; cnt_k++)
			{
				fprintf(file_pointer, "%02X ", (unsigned char)Server->DB[cnt_i].DB_UIDC[cnt_j][cnt_k]);
			}
			fputs("\n", file_pointer);
		}

		fputs("--TagC--\n", file_pointer);
		for (cnt_j = 0; cnt_j < HASH_DIGEST_BYTE; cnt_j++)
		{
			fprintf(file_pointer, "%02X ", (unsigned char)Server->DB[cnt_i].DB_TagC[cnt_j]);
		}
			fputs("\n", file_pointer);

		fputs("--Encrypted Client File--\n", file_pointer);
		for (cnt_j = 0; cnt_j < CLIENT_FILE_LEN_PADDING; cnt_j++)
		{
			fprintf(file_pointer, "%02X ", (unsigned char)Server->DB[cnt_i].DB_Ct_Client_File[cnt_j]);
		}
			fputs("\n", file_pointer);
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

int64_t cpucycles(void)
{
	return __rdtsc();
}