#include"header.h"

#if 1

//*****************************************************[Initialize the miracl system]************************************************************
Miracl precision = 100;
miracl* mip = mirsys(5000, 160); 
int cnt_i=0,cnt_j=0,cnt_k = 0;

int main()
{
	_CLIENT_ Client = { 0x00, };

//*****************************************************[STEP 1]***************************************************************
	printf("\n****************************************[STEP 1]*******************************************************\n\n");

	printf("\n---------------------------------[Client Generating Key using SHA-256]---------------------------------\n");
	Hash_Function_using_SHA_256((&Client)->Pt_Client_File, CLIENT_FILE_LEN, (&Client)->Client_Tag); //key generation using File
	Generating_key_using_256_digest((&Client)->Client_File_key, 16, (&Client)->Client_Tag);


	//---Check Hash_Function_using_SHA_256
	printf("\n------------[Hashing File] = ");
	Print_char((&Client)->Client_Tag, HASH_DIGEST_BYTE);
	
	printf("\n------------[Client_Key] = ");
	Print_char((&Client)->Client_File_key, 16);
	

	printf("\n---------------------------------[Client AES-128 CBC mode]---------------------------------\n");
	Client_Encryption_using_AES_128_CBC((&Client)->Pt_Client_File, CLIENT_FILE_LEN, (&Client)->Ct_Client_File, (&Client)->Client_File_key); //Encrypt Clinet File key generated in Hash_Function_using_SHA_256
	printf("\n----------[Ecrypted Client_File]---------\n");
	Print_char((&Client)->Ct_Client_File, CLIENT_FILE_LEN_PADDING);

	printf("\n---------------------------------[Client generates Tag of CipherText]---------------------------------\n");
	Hash_Function_using_SHA_256((&Client)->Ct_Client_File, CLIENT_FILE_LEN_PADDING, (&Client)->Client_Tag);//Tag generation using File encrypted

	printf("\n---------------------------------[Client_Tag]---------------------------------\n");
	Print_char((&Client)->Client_Tag, HASH_DIGEST_BYTE);

	//*****************************************************[STEP 2]************************************************************






	big x = mirvar(256256); //initialize n, must have
	big y = mirvar(1); //initialize n, must have
	big z = mirvar(0);

	//cotnum(n, stdin);
	cotnum(x, stdout);
	cotnum(y, stdout);

	add(x, y, z);
	cotnum(z,stdout);



	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve

	time_t seed;
	G1 Alice, Bob, sA, sB;
	G2 B6, Server, sS;
	GT res, sp, ap, bp;
	Big ss, s, a, b;
	


	time(&seed);
	irand((long)seed);

	//-------------------------------------------------------[T E S T_ Start]-------------------------------------------------------
	G1 P, rP, sP, result_G1;
	G2 H, sH, result_G2;
	GT result_pairing, result_power_pairing;
	Big r;
	Big Key;

	pfc.hash_and_map(H, (char*)"My name is Alice");
	pfc.hash_and_map(P, (char*)"Time Server");

	pfc.random(s);
	pfc.random(r);

	sH = pfc.mult(H, s);
	rP = pfc.mult(P, r);
	result_pairing = pfc.pairing(sH, rP);
	Key = pfc.hash_to_aes_key(result_pairing);
	cout << "e (sH,rP) =  " << Key << endl; printf("\n");
	cout << "e (sH,rP) =  " << pfc.hash_to_aes_key(result_pairing) << endl; printf("\n");
	//--------------------------------------------------------------------------------------------------

	result_pairing = pfc.pairing(H, P);
	result_power_pairing = pfc.power(result_pairing, r);
	result_power_pairing = pfc.power(result_power_pairing, s);
	cout << "e (H,P)^s*r = " << pfc.hash_to_aes_key(result_power_pairing) << endl; printf("\n");
	//--------------------------------------------------------------------------------------------------  


	sP = pfc.mult(P, s);
	result_pairing = pfc.pairing(H, sP);
	result_power_pairing = pfc.power(result_pairing, r);
	cout << "e (H,sP)^r = " << pfc.hash_to_aes_key(result_power_pairing) << endl; printf("\n");
	//--------------------------------------------------------------------------------------------------



//-------------------------------------------------------[T E S T_ End]-------------------------------------------------------


	//! ------------------------------------------------------[ AES TEST ]--------------------------------------------
	char Mr_AES_Key_128bit[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	char buff[PT_LEN] = {0x00,0x00};
	char IV_vector_CBC[16] = {0x00};

	aes a_1 = { {0x00}, };
	aes* pt_a = &a_1;
	
	//! AES init
	printf("\n----------[AES128 TEST]---------\n");
	aes_init(pt_a, MR_CBC, 16, Mr_AES_Key_128bit, IV_vector_CBC);
	Print_char(buff, PT_LEN);


	//! AES encrypt
	aes_encrypt(pt_a, buff);
	Print_char(buff, PT_LEN);


	//! AES decrypt
	aes_decrypt(pt_a, buff);
	Print_char(buff, PT_LEN);

	aes_end(pt_a);

	//! ------------------------------------------------------[ SHA TEST ]--------------------------------------------

	//sha256 psh = { {0x00}, };

	//sha256* pt_psh = &psh;

	//char hash[HASH_LEN] = {0x00};
	//char test[] = "Crypto Optimization and Application Lab Avengers";

	////! SHA init
	//shs256_init(pt_psh);

	//for (cnt_i = 0; test[cnt_i] != 0; cnt_i++)
	//{
	//	shs256_process(pt_psh, test[cnt_i]);
	//}
	////!
	//shs256_hash(pt_psh, hash);

	//printf("\n----------[SHA256 TEST]---------\n");
	//Print_char(hash, HASH_LEN);



	//! ------------------------------------------------------[ Strong DRBG TEST ]-------------------------------------------

	//time_t seed = 0x00;
	csprng rng = { {0x00}, };
	csprng* pt_rng = &rng;
	char random_byte[EXTRACT_RANDOMLEN] = { 0x00 };

	/*char raw[256] = {0x00};
	printf("Enter Raw random string= ");
	scanf("%s", raw);
	getchar();*/

	char raw[256] = {0x00};
	//time(&seed);
	seed = 0x1233223;
	strong_init(pt_rng, strlen(raw), raw, (long)seed);

	for (cnt_i = 0; cnt_i < EXTRACT_RANDOMLEN; cnt_i++)
	{
		random_byte[cnt_i] = (unsigned char) strong_rng(pt_rng);
	}


	printf("\n----------[Strong Random Generater TEST]---------\n");
	Print_char(random_byte, EXTRACT_RANDOMLEN);


	/*system("pause");*/
	return 0;
}

#endif

