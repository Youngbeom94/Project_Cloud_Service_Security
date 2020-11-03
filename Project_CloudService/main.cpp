#include"header.h"

#if 1

//*****************************************************[Initialize the miracl system]************************************************************
Miracl precision = 100;
miracl* mip = mirsys(5000, 160);
PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
int len = 0x00;
int cnt_i = 0, cnt_j = 0, cnt_k = 0;
G1 P;


//*****************************************************[Start]************************************************************
int main()
{
	_CLIENT_ Client = { 0x00, };
	_SERVER_ Server = { 0x00, };
	_TIME_SERVER_ Time_Server = { 0x00, };
	pfc.random(P); // P generation 

	printf("**********************[Client Run system]*************************\n");

	Initialize_Time_Server(&Time_Server);

	printf("*************[Client Generates Key, C, TagC from File]************\n");
	Client_generates_K_C_TagC(&Client);

	printf("*************[Client Checks if TagC is in Server]*****************\n");
	Client_check_to_Server_TacC(&Client, &Server);

	if ((&Client)->DB_Flag == TRUE)
	{
		printf("*************[Server add Client into UIDC]********************\n");
		printf("*************[End System]*************\n");
		return 0;
	}

	printf("*************[Client Generates H(t), R, LC, sd]*******************\n");
	Client_Generates_ht_R_LC_sd(&Client, &Server, &Time_Server);


	printf("*************[Server Verfiy TagC]*********************************\n");
	Server_Verifiy_TagC(&Client, &Server, &Time_Server);

	if ((&Server)->Tag_Flag == FALSE)
	{
		printf("*************[Server add Client into Black list]**************\n");
		printf("*************[End System]*************\n");
		return 0;
	}

	printf("*************[ All processes were executed normally ]*************\n");
	printf("**************************[End System]****************************\n");

	return 0;
	/*printf("\n--[Ecrypted Client_File]\n");
	Print_char((&Client)->Ct_Client_File, CLIENT_FILE_LEN_PADDING);


	printf("\n--[Client_Tag]\n");
	Print_char((&Client)->Client_Tag, HASH_DIGEST_BYTE);

	printf("\n--[Decrypted LC to C]\n");
	Print_char((&Server)->DBL_C_decrypted_by_LC, CLIENT_FILE_LEN_PADDING);


	printf("\n--[TagC of SerVeR]\n");
	Print_char((&Server)->DBL_TagC, HASH_DIGEST_BYTE);*/

}

#endif


void Client_generates_K_C_TagC(_CLIENT_* Client)
{
	/* This Function is Step 1
	* 1st:  Do Generates Key from given File, using SHA-256
	* 2nd:  Do Encrypt File, using generated key. In here we use AES-128 CBC Mode
	* 3rd:  Generates TagC from Encrypted File, using SHA-256
	*/
	//Read File
	Client_Read_File(Client);
	printf("Client read File Complete\n");

	//key generation using File
	printf("\n***[ Choose number Crypto for Hashing File ]***\n");
	printf("     1 : SHA-256, 2 : SHA-512, 3 : SHA-3  \n");
	scanf_s("%d", &(Client)->Hashing_Flag);
	Client_Hashing_File((Client)->Client_Tag, (Client)->Pt_Client_File, CLIENT_FILE_LEN, (Client)->Hashing_Flag);

	Generating_key_using_fixed_digest((Client)->Client_File_key, AES_KEY_LEN, (Client)->Client_Tag);
	printf("Client generates Key of File Complete\n");

	//Encrypt Clinet File key generated in Hash_Function_using_SHA_256
	printf("\n***[ Choose number Crypto for Encryption File ]***\n");
	printf("     1 : AES-128, 2 : LEA-128, 3 : SEED-128  \n");
	scanf_s("%d", &(Client)->Crypto_Flag);
	Client_Encrypte_File((Client)->Ct_Client_File,(Client)->Pt_Client_File, (Client)->Client_File_key,CLIENT_FILE_LEN, (Client)->Crypto_Flag);
	printf("Client generates  Encrypted File Complete\n");

	Client_Hashing_File((Client)->Client_Tag, (Client)->Ct_Client_File, CLIENT_FILE_LEN_PADDING, (Client)->Hashing_Flag);
	printf("Client generates  TagC of Encrypted File Complete\n\n");
}

void Client_check_to_Server_TacC(_CLIENT_* Client, _SERVER_* Server)
{
	/* This Function is Step 2
	 * 1st:    Client check that Server has TagC
	 * 2nd-1:  if TagC not in Server Client's DB_Flag is FALSE
	 * 2nd-2:  if TagC  in Server Client's DB_Flag is TRUE
	*/
	Client_Check_TagC_in_DB(Client, Server);
}

void Client_Generates_ht_R_LC_sd(_CLIENT_* Client, _SERVER_* Server, _TIME_SERVER_* Time_Server)
{
	/* This Function is Step 3
	 * 1st: Client generates ht = H(t); t is time (string). if server time is not same on t, then server can't decrypt LC
	 * 2nd: Client generates R = rP and pairing sd = e(ht,Q)^r
	 * 3rd: Client Generates LC = (rs,C) where rs = hash to AES_Key(sd)
	 * 4th: Client Delete FIle F from his storage and send t,R, LC, TagC to Server
	*/

	int Crypto_Flag = -1;
	// ************[[Client]
	// Client generates ht = H(t); t is time(string). if server time is not same on t, then server can't decrypt LC
	printf("Client set time and generates ht = H(t) complete\n");
	pfc.hash_and_map((Client)->ht, (Client)->t); //ht generation using t

	//Client generates R = rP and pairing sd = e(ht, Q) ^ r
	pfc.random((Client)->r); //r generation
	(Client)->rP = pfc.mult(P, (Client)->r); //R = rP
	printf("Client generates R = rp complete\n");
	(Client)->sd = pfc.pairing((Client)->ht, (Time_Server)->TS_Public_Key); //sd = e(ht,Q)
	(Client)->sd = pfc.power((Client)->sd, (Client)->r); // sd = e(ht,Q)^r
	printf("Client generates sd = e(ht,Q)^r complete\n");


	(Client)->rs = pfc.hash_to_aes_key((Client)->sd); //rs = hashing(sd)_to AES_KEY
	printf("Client generates key from the sd = e(ht,Q)^r complete\n");

	big temp; 	// Since type of rs is 'big', we need to change 'big' to 'bytes' for using AES
	char temp_for_handling_AES_KEY[16] = { 0x00 }; //this is AES key generated by rs
	temp = (Client)->rs.getbig(); //cotnum(temp, stdout); 
	big_to_bytes(AES_KEY_LEN, temp, temp_for_handling_AES_KEY, TRUE);

	//Encrypt Clinet File key generated in Hash_Function_using_SHA_256
	printf("\n***[ Choose number Crypto for Encryption LC ]***\n");
	printf("     1 : AES-128, 2 : LEA-128, 3 : SEED-128, 4 : XoR_based  \n");
	scanf_s("%d", &(Client)->Crypto_Flag);
	Client_Encrypte_C_to_LC((Client)->Ct_LC_File, (Client)->Ct_Client_File, temp_for_handling_AES_KEY, CLIENT_FILE_LEN_PADDING, (Client)->Crypto_Flag);
	printf("Client generates LC of C complete\n");

	//Client Delete FIle F from his storage and send t, R, LC, TagC to Server
	(Server)->Hashing_Flag = (Client)->Hashing_Flag;
	(Server)->Crypto_Flag = (Client)->Crypto_Flag;
	Copy_char((Server)->DBL_LC_File, (Client)->Ct_LC_File, CLIENT_FILE_LEN_PADDING);
	Copy_char((Server)->t, (Client)->t, TIME_LEN);
	printf("Client send t, R, LC, TagC to Server complete\n\n");

}

void Server_Verifiy_TagC(_CLIENT_* Client, _SERVER_* Server, _TIME_SERVER_* Time_Server)
{
	/* This Function is Step 4
	 * 1st: Server get Ts = sH(t), from txt file generated by Time_Server
	 * 2nd: Server operates sd = e(Ts,R) and generates rs for AES, using sd ; proof : sd = e(Ts,R) = e(sH(t),rP) = e(H(t),P)^sr = e(H(t),sP)^r
	 * 3rd: Server Decrypt C = UnLock (rs,LC), here rs is key of AES
	 * 4th: Server generates TagC, using C decrypted 3rd
	 * 5th: if TagC is not in Server. add DB and deletes DBL, else verify TagC
	*/

	int cnt_i = 0;
	char current_time[TIME_LEN] = { 0x00 };
	char time_buff[TIME_LEN] = { 0x00 };
	ZZn2 G2_P1, G2_P2;
	Big point1_x = { 0x00 }, point1_y = { 0x00 }, point2_x = { 0x00 }, point2_y = { 0x00 };
	big big_point1_x = mirvar(0), big_point1_y = mirvar(0), big_point2_x = mirvar(0), big_point2_y = mirvar(0);
	FILE* file_pointer;

	struct tm* t;
	time_t timer;
	timer = time(NULL);
	t = localtime(&timer); // add strcuture using localtime
	sprintf(current_time, "%04d%02d%02d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

	file_pointer = fopen("Time_Server.txt", "r");

	for (cnt_i = 0; cnt_i <= TIME_SERVER_BUFF + 10; cnt_i++)
	{
		fgetc(file_pointer); //read '['
		fgets(time_buff, 9, file_pointer); //read "yyyymmdd"
		fgetc(file_pointer); //read ']'
		fgetc(file_pointer); //read 'NULL_C'

		mip->IOBASE = 256;
		mip->INPLEN = BNCURVE_POINTLEN * 2;
		cinnum(big_point1_x, file_pointer); //read 'x of point1'
		cinnum(big_point1_y, file_pointer); //read 'y of point1'
		cinnum(big_point2_x, file_pointer); //read 'x of point2'
		cinnum(big_point2_y, file_pointer); //read 'y of point2'

		fgetc(file_pointer); //read '\n'

		if (char_compare(current_time, time_buff, TIME_LEN) == TRUE)
		{
			break; //get current Ts from Time_Server 
		}
		else
		{
			if (cnt_i == TIME_SERVER_BUFF)
			{
				printf("Server Can't found Ts of Current day\n");
				break;
			}
			continue; // if time_buff is not same to current time, then continue loof
		}

	}
	point1_x = Big(big_point1_x);
	point1_y = Big(big_point1_y);
	point2_x = Big(big_point2_x);
	point2_y = Big(big_point2_y);

	G2_P1.set(point1_x, point1_y);
	G2_P2.set(point2_x, point2_y);

	(Time_Server)->Ts.g.set(G2_P1, G2_P2);
	//cout << (Time_Server)->Ts.g << endl;

	printf("------Server get Ts from Time_Server\n");

	// ************[Server]
	(Server)->sd = pfc.pairing((Time_Server)->Ts, (Client)->rP); //sd = e(ht,Q) ;here Q = rP
	printf("------Server generates sd = e(ht,Q) Complete\n");
	(Server)->rs = pfc.hash_to_aes_key((Server)->sd); //rs = hashing(sd)_to AES_KEY
	printf("------Server generates rs from sd = e(ht,Q) Complete\n");

	// Since type of rs is 'big', we need to change 'big' to 'bytes' for using AES
	big temp2;
	char temp2_for_handling_AES_KEY_used_in_Ts[16] = { 0x00 };
	temp2 = (Server)->rs.getbig(); //cotnum(temp, stdout); //rs is big. big to bytes
	big_to_bytes(AES_KEY_LEN, temp2, temp2_for_handling_AES_KEY_used_in_Ts, TRUE);
	Copy_char((Server)->rs_key, temp2_for_handling_AES_KEY_used_in_Ts, AES_KEY_LEN);


	// Server decryptes LC to C
	Server_Decrypt_LC_to_C((Server)->DBL_C_decrypted_by_LC,(Server)->DBL_LC_File,(Server)->rs_key, CLIENT_FILE_LEN_PADDING,(Server)->Crypto_Flag);
	printf("------Server decrypts LC Complete\n");

	// Server generates TagC using SHA-256
	Server_Hashing_File_to_Tag((Server)->DBL_TagC, (Server)->DBL_C_decrypted_by_LC, CLIENT_FILE_LEN_PADDING,(Server)->Hashing_Flag);//Tag generation using File encrypted
	printf("------Server generates TagC from the decrypted LC Complete\n");

	// Server verify TagC
	printf("------Server verificates TagC\n");
	Server_Tag_Verification((Server)->DBL_TagC, (Client)->Client_Tag, HASH_DIGEST_BYTE, &((Server)->Tag_Flag));

	Hash_Function_using_SHA_256(Client->name, Client_Name_Len, Server->DB_UIDC[Server->Client_Numeber]);


	Copy_char((Server)->DB_TagC[Server->Client_Numeber], (Server)->DBL_TagC, HASH_DIGEST_BYTE);
	Copy_char((Server)->DB_Ct_Client_File, (Server)->DBL_C_decrypted_by_LC, CLIENT_FILE_LEN_PADDING);
	//Write TagC, Cipher, and DB_UIDC  data to File
	Server_Write_File(Server);
}

void Initialize_Time_Server(_TIME_SERVER_* Time_Server)
{
	/* This Function is Initialize_Time_Server
	 * 1st:  Generate both Secret_Key (s) and Public_key (Q = sP) of Time_Server
	 * 2nd:  Generate Ts = sH(t) for each day
	 * 3rd:  Generates TagC from Encrypted File, using SHA-256

	 * Initialize_Time_Server() outputs Ts = sH(t) to a file for each date.
	 * Here, Ts is an element of G2 in pairing operation, so the file is stored for two points G2 = ((x1,y1), (x2,y2)).
	 * In this function, there is a process of converting and storing strings.
	*/

	int cnt_i = 0;
	unsigned int year = 0, month = 0, date = 0;
	ZZn2 A, B;
	Big point1_x, point1_y, point2_x, point2_y;
	big big_point1_x, big_point1_y, big_point2_x, big_point2_y;
	FILE* file_pointer;
	struct tm* t;
	time_t timer;

	printf("Time_Server Initialization\n");

	file_pointer = fopen("Time_Server.txt", "w");

	// ************[TIme server]
	// Generate both Secret_Key (s) and Public_key (Q = sP) of Time_Server
	pfc.random((Time_Server)->TS_Secret_Key); //secret key generation
	(Time_Server)->TS_Public_Key = pfc.mult(P, (Time_Server)->TS_Secret_Key); //public key generation Q = sP

	//  Generate Ts = sH(t) for each day


	for (cnt_i = TIME_SERVER_BUFF; cnt_i >= 0; cnt_i--)
	{

		timer = time(NULL) - ((unsigned long long)86400 * (unsigned long long)cnt_i); //chose offset of each day
		t = localtime(&timer); // add strcuture using localtime
		date = t->tm_mday; // date cacluation
		month = t->tm_mon + 1; // month cacluation
		year = t->tm_year + 1900; // year cacluation

		sprintf((Time_Server)->t, "%04d%02d%02d", year, month, date); //t set
		pfc.hash_and_map((Time_Server)->Ts, (Time_Server)->t); //Ts = H(t) = ht
		(Time_Server)->Ts = pfc.mult((Time_Server)->Ts, (Time_Server)->TS_Secret_Key); //Ts = sH(t) = sht

		//get two point of G2
		(Time_Server)->Ts.g.get(A, B);
		A.get(point1_x, point1_y);
		B.get(point2_x, point2_y);

		//convert G2 to big
		big_point1_x = point1_x.getbig();
		big_point1_y = point1_y.getbig();
		big_point2_x = point2_x.getbig();
		big_point2_y = point2_y.getbig();

		//write to file
		fprintf(file_pointer, "[%04d%02d%02d]\n", year, month, date);
		cotnum(big_point1_x, file_pointer);
		cotnum(big_point1_y, file_pointer);
		cotnum(big_point2_x, file_pointer);
		cotnum(big_point2_y, file_pointer);
		fputs("\n", file_pointer);
	}

	fclose(file_pointer);

	printf("Time_Server Publishing Ts file complete\n\n");
}

# if 0
//[밑은 테스트코드 입니다] * ***********************************************************************************************************************************************************************
//
//	{
//	big to binary using len
//		int len2;
//	char test2[100];
//	len2 = to_binary((&time_server)->rs, 100, test2, false); //true,false justified with leading zero
//
//	printf("rs = \n");
//	for (cnt_i = 0; cnt_i < 100; cnt_i++)
//	{
//		printf("%02x", (unsigned char)test2[cnt_i]);
//	}
//
//
//
//
//
//
//
//
//	------------------------------------------------------ - [t e s t_ start]------------------------------------------------------ -
//
//************************************************************[G1 -> char]*****************************************************************************
//
//
//	G1 p;
//	big x, y;
//	big big_x, big_y;
//	pfc.random(p);
//	cout << p.g << endl;
//
//	char tempx[32] = { 0x00 };
//	char tempy[32] = { 0x00 };
//	p.g.getxy(x, y);
//	big_x = x.getbig();
//	big_y = y.getbig();
//	big_to_bytes(32, big_x, tempx, true);
//	big_to_bytes(32, big_y, tempy, true);
//
//	print_char(tempx, 32);
//	print_char(tempy, 32);
//
//	x = from_binary(32, tempx);
//	y = from_binary(32, tempy);
//	p.g.set(x, y);
//	cout << p.g << endl;
//
//
//	************************************************************[G2->char] * ****************************************************************************
//
//		G2 P;
//	pfc.random(P); //secret key generation
//	cout << P.g << endl;
//
//	ZZn2 A, B;
//	Big x1, y1, x2, y2;
//	big big_x1, big_y1, big_x2, big_y2;
//	char tempx1[32] = { 0x00 };
//	char tempy1[32] = { 0x00 };
//
//	char tempx2[32] = { 0x00 };
//	char tempy2[32] = { 0x00 };
//
//	P.g.get(A, B);
//
//	A.get(x1, y1);
//
//	B.get(x2, y2);
//
//	cout << A << endl;
//	cout << B << endl;
//
//	big_x1 = x1.getbig();
//	big_y1 = y1.getbig();
//
//	big_x2 = x2.getbig();
//	big_y2 = y2.getbig();
//
//	big_to_bytes(32, big_x1, tempx1, TRUE);
//	big_to_bytes(32, big_y1, tempy1, TRUE);
//
//
//	big_to_bytes(32, big_x2, tempx2, TRUE);
//	big_to_bytes(32, big_y2, tempy2, TRUE);
//
//	Print_char(tempx1, 32);
//	Print_char(tempy1, 32);
//
//	Print_char(tempx2, 32);
//	Print_char(tempy2, 32);
//
//
//	ZZn2 C, D;
//	Big x11, y11, x22, y22;
//	big big_x11, big_y11, big_x22, big_y22;
//	G2 Q;
//
//
//	x11 = from_binary(32, tempx1);
//	y11 = from_binary(32, tempy1);
//	x22 = from_binary(32, tempx2);
//	y22 = from_binary(32, tempy2);
//
//	C.set(x11, y11);
//	D.set(x22, y22);
//
//	Q.g.set(C, D);
//
//	cout << Q.g << endl;
//
//	************************************************************[Printf] * ****************************************************************************
//	g1 p, rp, sp, result_g1;
//	g2 h, sh, result_g2;
//	cout << p.g << endl;
//	gt result_pairing, result_power_pairing;
//	big r;
//	big key;
//
//	pfc.hash_and_map(h, (char*)"my name is alice");
//	pfc.hash_and_map(p, (char*)"time server");
//
//	pfc.random(s);
//	pfc.random(r);
//
//	sh = pfc.mult(h, s);
//	rp = pfc.mult(p, r);
//	result_pairing = pfc.pairing(sh, rp);
//	key = pfc.hash_to_aes_key(result_pairing);
//	cout << "e (sh,rp) =  " << key << endl; printf("\n");
//	cout << "e (sh,rp) =  " << pfc.hash_to_aes_key(result_pairing) << endl; printf("\n");
//	//--------------------------------------------------------------------------------------------------
//
//	result_pairing = pfc.pairing(h, p);
//	result_power_pairing = pfc.power(result_pairing, r);
//	result_power_pairing = pfc.power(result_power_pairing, s);
//	cout << "e (h,p)^s*r = " << pfc.hash_to_aes_key(result_power_pairing) << endl; printf("\n");
//	//--------------------------------------------------------------------------------------------------  
//
//
//	sp = pfc.mult(p, s);
//	result_pairing = pfc.pairing(h, sp);
//	result_power_pairing = pfc.power(result_pairing, r);
//	cout << "e (h,sp)^r = " << pfc.hash_to_aes_key(result_power_pairing) << endl; printf("\n");
//	--------------------------------------------------------------------------------------------------
//
//
//
//		------------------------------------------------------ - [t e s t_ end]------------------------------------------------------ -
//
//
//	big x = mirvar(256256); //initialize n, must have
//	big y = mirvar(1); //initialize n, must have
//	big z = mirvar(0);
//
//	//cotnum(n, stdin);
//	cotnum(x, stdout);
//	cotnum(y, stdout);
//
//	add(x, y, z);
//	cotnum(z, stdout);
//
//
//
//
//	time_t seed;
//	g1 alice, bob, sa, sb;
//	g2 b6, server, ss;
//	gt res, sp, ap, bp;
//	big ss, s, a, b;
//
//
//	time(&seed);
//	irand((long)seed);
//
//
//	!------------------------------------------------------[aes test]--------------------------------------------
//		char mr_aes_key_128bit[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
//	char buff[pt_len] = { 0x00,0x00 };
//	char iv_vector_cbc[16] = { 0x00 };
//
//	aes a_1 = { {0x00}, };
//	aes* pt_a = &a_1;
//
//	//! aes init
//	printf("\n----------[aes128 test]---------\n");
//	aes_init(pt_a, mr_cbc, 16, mr_aes_key_128bit, iv_vector_cbc);
//	print_char(buff, pt_len);
//
//
//	//! aes encrypt
//	aes_encrypt(pt_a, buff);
//	print_char(buff, pt_len);
//
//
//	//! aes decrypt
//	aes_decrypt(pt_a, buff);
//	print_char(buff, pt_len);
//
//	aes_end(pt_a);
//
//	!------------------------------------------------------[sha test]--------------------------------------------
//
//		sha256 psh = { {0x00}, };
//
//	sha256* pt_psh = &psh;
//
//	char hash[hash_len] = { 0x00 };
//	char test[] = "crypto optimization and application lab avengers";
//
//	//! sha init
//	shs256_init(pt_psh);
//
//	for (cnt_i = 0; test[cnt_i] != 0; cnt_i++)
//	{
//		shs256_process(pt_psh, test[cnt_i]);
//	}
//	//!
//	shs256_hash(pt_psh, hash);
//
//	printf("\n----------[sha256 test]---------\n");
//	print_char(hash, hash_len);
//
//
//
//	!------------------------------------------------------[strong drbg test]------------------------------------------ -
//
//		//time_t seed = 0x00;
//		csprng rng = { {0x00}, };
//	csprng* pt_rng = &rng;
//	char random_byte[extract_randomlen] = { 0x00 };
//
//	/*char raw[256] = {0x00};
//	printf("enter raw random string= ");
//	scanf("%s", raw);
//	getchar();*/
//
//	char raw[256] = { 0x00 };
//	//time(&seed);
//	seed = 0x1233223;
//	strong_init(pt_rng, strlen(raw), raw, (long)seed);
//
//	for (cnt_i = 0; cnt_i < extract_randomlen; cnt_i++)
//	{
//		random_byte[cnt_i] = (unsigned char)strong_rng(pt_rng);
//	}
//
//
//	printf("\n----------[strong random generater test]---------\n");
//	print_char(random_byte, extract_randomlen);
//
//
//	/*system("pause");*/
//}
#endif