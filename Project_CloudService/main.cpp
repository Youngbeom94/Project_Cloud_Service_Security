#include"header.h"

#if 1

//*****************************************************[Initialize the miracl system]************************************************************
Miracl precision = 100;
miracl* mip = mirsys(5000, 160); 
PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
int len = 0x00;

int cnt_i=0,cnt_j=0,cnt_k = 0;

//*****************************************************[Start]************************************************************
int main()
{
	_CLIENT_ Client = { 0x00, };
	_SERVER_ Server = { 0x00, };
	_TIME_SERVER_ Time_Server = { 0x00, };





	//Time Server Initiallize



	Initialize_Time_Server(&Time_Server);


	Client_Read_File(&Client);

	Step_1_Client_generates_k_C_TagC(&Client);
	
	Step_2_Client_check_to_Server_TacC(&Client,&Server);
	

	Step_3_Client_generates_sd_pairing(&Client, &Server, &Time_Server);


	Step_4_Server_Verifiy_Server_TacC(&Client, &Server, &Time_Server);
	
	printf("\n--[Ecrypted Client_File]\n");
	Print_char((&Client)->Ct_Client_File, CLIENT_FILE_LEN_PADDING);


	printf("\n--[Client_Tag]\n");
	Print_char((&Client)->Client_Tag, HASH_DIGEST_BYTE);

	printf("\n--[Decrypted LC to C]\n");
	Print_char((&Server)->DBL_C_decrypted_by_LC, CLIENT_FILE_LEN_PADDING);


	printf("\n--[TagC of SerVeR]\n");
	Print_char((&Server)->DBL_TagC, HASH_DIGEST_BYTE);

	return 0;
}

#endif


void Initialize_Time_Server(_TIME_SERVER_* Time_Server)
{
	int cnt_i = 0;
	unsigned int year = 0, month = 0, date = 0;
	FILE* file_pointer;
	file_pointer = fopen("Time_Server.txt", "w");

	// ************[TIme server]
	// Time_Server generates Ts = sH(t), using current time
	struct tm* t;
	time_t timer;

	//for (cnt_i = 0; cnt_i < 50; cnt_i++)
	{

		timer = time(NULL) + ((unsigned long long)86400 * (unsigned long long)cnt_i);
		t = localtime(&timer); // add strcuture using localtime
		date = t->tm_mday;
		year = t->tm_year + 1900;
		month = t->tm_mon + 1;

		fprintf(file_pointer, "%04d%02d%02d : ", year, month, date);

		sprintf((Time_Server)->t, "%04d%02d%02d", year, month, date);

		pfc.hash_and_map((Time_Server)->Ts, (Time_Server)->t); //Ts = H(t) = ht
		pfc.random((Time_Server)->TS_Secret_Key); //secret key generation
		(Time_Server)->Ts = pfc.mult((Time_Server)->Ts, (Time_Server)->TS_Secret_Key); //Ts = sH(t) = sht


		//!G2가 변환이 안돼 그래서 퍼블리싱이 오류가 생기는 중이다.
		//cout << (Time_Server)->Ts.g << endl;
	}


	fclose(file_pointer);
}

void Step_1_Client_generates_k_C_TagC(_CLIENT_* Client)
{
	/* This Function is Step 1
	 * 1st:  Do Generates Key from given File, using SHA-256
	 * 2nd:  Do Encrypt File, using generated key. In here we use AES-128 CBC Mode
	 * 3rd:  Generates TagC from Encrypted File, using SHA-256
	*/


	//key generation using File
	Hash_Function_using_SHA_256((Client)->Pt_Client_File, CLIENT_FILE_LEN, (Client)->Client_Tag);
	Generating_key_using_256_digest((Client)->Client_File_key, AES_KEY_LEN, (Client)->Client_Tag);

	//Encrypt Clinet File key generated in Hash_Function_using_SHA_256
	Client_Encryption_using_AES_128_CBC((Client)->Pt_Client_File, CLIENT_FILE_LEN, (Client)->Ct_Client_File, (Client)->Client_File_key);

	//Tag generation using File encrypted
	Hash_Function_using_SHA_256((Client)->Ct_Client_File, CLIENT_FILE_LEN_PADDING, (Client)->Client_Tag);

}


void Step_2_Client_check_to_Server_TacC(_CLIENT_* Client, _SERVER_* Server)
{
	/* This Function is Step 2
	 * 1st:    Client check that Server has TagC
	 * 2nd-1:  if TagC not in Server Client's DB_Flag is FALSE
	 * 2nd-2:  if TagC  in Server Client's DB_Flag is TRUE
	*/

	Client_Check_TagC_in_DB(Client, Server);
}

void Step_3_Client_generates_sd_pairing(_CLIENT_* Client, _SERVER_* Server, _TIME_SERVER_* Time_Server)
{
	/* This Function is Step 3
	 * 1st: Time_Server generates Secret_key = s and Public_key = Q = sP
	 * 2nd: Client generates ht = H(t); t is time (string). if server time is not same on t, then server can't decrypt LC
	 * 3rd: Client generates R = rP and pairing sd = e(ht,Q)^r
	 * 4th: Client Generates LC = (rs,C) where rs = hash to AES_Key(sd)
	 * 5th: Client Delete FIle F from his storage and send t,R, LC, TagC to Server
	*/

	//PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve

	G1 P;
	pfc.random(P); //case 1 : P generation 
	
	//pfc.hash_and_map(P, (char*)"Prime for Pairing"); //case 2: P generation 



	// ************[TIme server]
	// Time_Server generates Secret_key = s and Public_key = Q = sP
	//pfc.random((Time_Server)->TS_Secret_Key); //secret key generation
	(Time_Server)->TS_Public_Key = pfc.mult(P, (Time_Server)->TS_Secret_Key); //public key generation Q = sP

	// ************[[Client]
	// Client generates ht = H(t); t is time(string). if server time is not same on t, then server can't decrypt LC
	pfc.hash_and_map((Client)->ht, (Client)->t); //ht generation using t

	//Client generates R = rP and pairing sd = e(ht, Q) ^ r
	pfc.random((Client)->r); //r generation
	(Client)->rP = pfc.mult(P, (Client)->r); //R = rP
	(Client)->sd = pfc.pairing((Client)->ht, (Time_Server)->TS_Public_Key); //sd = e(ht,Q)
	(Client)->sd = pfc.power((Client)->sd, (Client)->r); // sd = e(ht,Q)^r


	//Client generates LC = (rs,C) where rs = hash to AES_Key(sd)

	(Client)->rs = pfc.hash_to_aes_key((Client)->sd); //rs = hashing(sd)_to AES_KEY


	big temp; 	// Since type of rs is 'big', we need to change 'big' to 'bytes' for using AES
	char temp_for_handling_AES_KEY[16] = { 0x00 }; //this is AES key generated by rs
	temp = (Client)->rs.getbig(); //cotnum(temp, stdout); 
	big_to_bytes(AES_KEY_LEN, temp, temp_for_handling_AES_KEY, TRUE);
	Client_Encryption_LC_using_AES_128_CBC((Client)->Ct_Client_File, CLIENT_FILE_LEN_PADDING, (Client)->Ct_LC_File, temp_for_handling_AES_KEY);// make LC

	//Client Delete FIle F from his storage and send t, R, LC, TagC to Server

	Copy_char((Server)->DBL_LC_File, (Client)->Ct_LC_File, CLIENT_FILE_LEN_PADDING);
	Copy_char((Server)->t, (Client)->t, TIME_LEN);

} 

void Step_4_Server_Verifiy_Server_TacC(_CLIENT_* Client, _SERVER_* Server, _TIME_SERVER_* Time_Server)
{
	/* This Function is Step 4
	 * 1st: Time_Server generates Ts = sH(t), using current time
	 * 2nd: Server operates sd = e(Ts,R) and generates rs for AES, using sd ; proof : sd = e(Ts,R) = e(sH(t),rP) = e(H(t),P)^sr = e(H(t),sP)^r
	 * 3rd: Server Decrypt C = UnLock (rs,LC), here rs is key of AES
	 * 4th: Server generates TagC, using C decrypted 3rd
	 * 5th: if TagC is not in Server. add DB and deletes DBL, else verify TagC
	*/


	// ************[TIme server]
	// Time_Server generates Ts = sH(t), using current time
	struct tm* t;
	time_t timer;

	timer = time(NULL);    // get sec of a current time
	t = localtime(&timer); // add strcuture using localtime

	sprintf((Time_Server)->t, "%04d%02d%02d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday	);

	pfc.hash_and_map((Time_Server)->Ts, (Time_Server)->t); //Ts = H(t) = ht
	(Time_Server)->Ts = pfc.mult((Time_Server)->Ts, (Time_Server)->TS_Secret_Key); //Ts = sH(t) = sht


	// ************[TIme server]
	(Server)->sd = pfc.pairing((Time_Server)->Ts, (Client)->rP); //sd = e(ht,Q) ;here Q = rP
	(Server)->rs = pfc.hash_to_aes_key((Server)->sd); //rs = hashing(sd)_to AES_KEY

	// Since type of rs is 'big', we need to change 'big' to 'bytes' for using AES
	big temp2;
	char temp2_for_handling_AES_KEY_used_in_Ts[16] = { 0x00 };
	temp2 = (Server)->rs.getbig(); //cotnum(temp, stdout); //rs is big. big to bytes
	big_to_bytes(AES_KEY_LEN, temp2, temp2_for_handling_AES_KEY_used_in_Ts, TRUE);
	Copy_char((Server)->rs_key, temp2_for_handling_AES_KEY_used_in_Ts, AES_KEY_LEN);


	// Server decryptes LC to C
	Server_LC_Decryption_using_AES_128_CBC((Server)->DBL_LC_File, CLIENT_FILE_LEN_PADDING, (Server)->DBL_C_decrypted_by_LC, (Server)->rs_key);// make LC

	// Server generates TagC using SHA-256
	Hash_Function_using_SHA_256((Server)->DBL_C_decrypted_by_LC, CLIENT_FILE_LEN_PADDING, (Server)->DBL_TagC);//Tag generation using File encrypted

	// Server verify TagC
	Server_Tag_Verification((Server)->DBL_TagC, (Client)->Client_Tag, HASH_DIGEST_BYTE, &((Server)->Tag_Flag));

	Hash_Function_using_SHA_256(Client->name, Client_Name_Len, Server->DB_UIDC[Server->Client_Numeber]);


	Copy_char((Server)->DB_TagC[Server->Client_Numeber], (Server)->DBL_TagC, HASH_DIGEST_BYTE);
	Copy_char((Server)->DB_Ct_Client_File, (Server)->DBL_C_decrypted_by_LC, CLIENT_FILE_LEN_PADDING);
	//Write TagC, Cipher, and DB_UIDC  data to File
	Server_Write_File(Server);
}




# if 0
//[ 밑은 테스트코드 입니다 ]************************************************************************************************************************************************************************

// Big to binary using len
//int len2;
//char test2[100];
//len2 = to_binary((&Time_Server)->rs, 100, test2, FALSE); //TRUE,FALSE justified with leading zero

//printf("rs = \n");
//for (cnt_i = 0; cnt_i < 100; cnt_i++)
//{
//	printf("%02x", (unsigned char)test2[cnt_i]);
//}








//-------------------------------------------------------[T E S T_ Start]-------------------------------------------------------


//G1 or G2 -> char


//G1 P;
//Big x, y;
//big big_x, big_y;
//pfc.random(P);
//cout << P.g << endl;
//
//char tempx[32] = { 0x00 };
//char tempy[32] = { 0x00 };
//P.g.getxy(x, y);
//big_x = x.getbig();
//big_y = y.getbig();
//big_to_bytes(32, big_x, tempx, TRUE);
//big_to_bytes(32, big_y, tempy, TRUE);
//
//Print_char(tempx, 32);
//Print_char(tempy, 32);
//
//x = from_binary(32, tempx);
//y = from_binary(32, tempy);
//P.g.set(x, y);
//cout << P.g << endl;


/////////////////////////////////////////////////////



/
//G1 P, rP, sP, result_G1;
//G2 H, sH, result_G2;
//cout << P.g << endl;
//GT result_pairing, result_power_pairing;
//Big r;
//Big Key;

//pfc.hash_and_map(H, (char*)"My name is Alice");
//pfc.hash_and_map(P, (char*)"Time Server");

//pfc.random(s);
//pfc.random(r);

//sH = pfc.mult(H, s);
//rP = pfc.mult(P, r);
//result_pairing = pfc.pairing(sH, rP);
//Key = pfc.hash_to_aes_key(result_pairing);
//cout << "e (sH,rP) =  " << Key << endl; printf("\n");
//cout << "e (sH,rP) =  " << pfc.hash_to_aes_key(result_pairing) << endl; printf("\n");
////--------------------------------------------------------------------------------------------------

//result_pairing = pfc.pairing(H, P);
//result_power_pairing = pfc.power(result_pairing, r);
//result_power_pairing = pfc.power(result_power_pairing, s);
//cout << "e (H,P)^s*r = " << pfc.hash_to_aes_key(result_power_pairing) << endl; printf("\n");
////--------------------------------------------------------------------------------------------------  


//sP = pfc.mult(P, s);
//result_pairing = pfc.pairing(H, sP);
//result_power_pairing = pfc.power(result_pairing, r);
//cout << "e (H,sP)^r = " << pfc.hash_to_aes_key(result_power_pairing) << endl; printf("\n");
//--------------------------------------------------------------------------------------------------



//-------------------------------------------------------[T E S T_ End]-------------------------------------------------------


	//big x = mirvar(256256); //initialize n, must have
	//big y = mirvar(1); //initialize n, must have
	//big z = mirvar(0);

	////cotnum(n, stdin);
	//cotnum(x, stdout);
	//cotnum(y, stdout);

	//add(x, y, z);
	//cotnum(z,stdout);




	//time_t seed;
	//G1 Alice, Bob, sA, sB;
	//G2 B6, Server, sS;
	//GT res, sp, ap, bp;
	//Big ss, s, a, b;
	

	//time(&seed);
	//irand((long)seed);


	//! ------------------------------------------------------[ AES TEST ]--------------------------------------------
	//char Mr_AES_Key_128bit[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	//char buff[PT_LEN] = {0x00,0x00};
	//char IV_vector_CBC[16] = {0x00};

	//aes a_1 = { {0x00}, };
	//aes* pt_a = &a_1;
	//
	////! AES init
	//printf("\n----------[AES128 TEST]---------\n");
	//aes_init(pt_a, MR_CBC, 16, Mr_AES_Key_128bit, IV_vector_CBC);
	//Print_char(buff, PT_LEN);


	////! AES encrypt
	//aes_encrypt(pt_a, buff);
	//Print_char(buff, PT_LEN);


	////! AES decrypt
	//aes_decrypt(pt_a, buff);
	//Print_char(buff, PT_LEN);

	//aes_end(pt_a);

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
//
//	//time_t seed = 0x00;
//	csprng rng = { {0x00}, };
//	csprng* pt_rng = &rng;
//	char random_byte[EXTRACT_RANDOMLEN] = { 0x00 };
//
//	/*char raw[256] = {0x00};
//	printf("Enter Raw random string= ");
//	scanf("%s", raw);
//	getchar();*/
//
//	char raw[256] = {0x00};
//	//time(&seed);
//	seed = 0x1233223;
//	strong_init(pt_rng, strlen(raw), raw, (long)seed);
//
//	for (cnt_i = 0; cnt_i < EXTRACT_RANDOMLEN; cnt_i++)
//	{
//		random_byte[cnt_i] = (unsigned char) strong_rng(pt_rng);
//	}
//
//
//	printf("\n----------[Strong Random Generater TEST]---------\n");
//	Print_char(random_byte, EXTRACT_RANDOMLEN);
//
//
//	/*system("pause");*/

#endif