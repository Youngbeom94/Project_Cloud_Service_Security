#pragma once
#define _CRT_SECURE_NO_WARNINGS 

#include <iostream>
#include <fstream>
#include <ctime>
#include <stdlib.h>
#include <time.h>
#include "zzn.h"
#include "miracl.h"
#include "big.h"
#include "ecn.h"


#define MR_PAIRING_BN    // AES-128 or AES-192 security
#include "pairing_3.h"



#define AES_SECURITY 128
#define AES_KEY_LEN 16
#define CLIENT_FILE_LEN 300
#define CLIENT_FILE_LEN_PADDING ((16-(CLIENT_FILE_LEN%16)) + CLIENT_FILE_LEN)
#define HASH_DIGEST_BYTE 32
#define EXTRACT_RANDOMLEN 32
#define BNCURVE_POINTLEN 32
#define PT_LEN 16
#define TIME_FLAG TRUE
#define TIME_LEN 9

#define Client_Name_Len 20
#define DB_Range 10
#define TRUE 1
#define FALSE 0


typedef struct __CLIENT_STRUCTURE__ {
	char name[Client_Name_Len] = "Alice";
	char Pt_Client_File[CLIENT_FILE_LEN];
	char Ct_Client_File[CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char Ct_LC_File[CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char Client_File_key[16] = { 0x00 };
	char Client_Tag[HASH_DIGEST_BYTE] = { 0x00 };

	char t[TIME_LEN] = "20201029";
	char Time_Flag = TRUE; //Time server authentication passed in all cases 
	char DB_Flag = FALSE; 

	G1 rP; //R = rP
	G2 ht;
	GT sd; 
	Big r;
	Big rs;
}_CLIENT_;


typedef struct __SERVER_STRUCTURE__ {
	// DB Part
	char DB_TagC[DB_Range][HASH_DIGEST_BYTE] = { 0x00,0x00 };
	char DB_Ct_Client_File[CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char DB_UIDC[DB_Range][HASH_DIGEST_BYTE] = { 0x00 };
	char Client_Numeber = 0x00;

	//DBL Part
	char t[TIME_LEN];
	G1 R; //R = rP
	char DBL_LC_File[CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char DBL_TagC[HASH_DIGEST_BYTE] = { 0x00,0x00 };
	char DBL_C_decrypted_by_LC[CLIENT_FILE_LEN_PADDING] = { 0x00,0x00 };
	char DBL_UIDC[DB_Range][HASH_DIGEST_BYTE] = { 0x00 };
	char Flag = TRUE; //Time server authentication passed in all cases 
	char rs_key[AES_KEY_LEN] = { 0x00 };
	char Tag_Flag = -1;

	GT sd;
	Big rs;

}_SERVER_;


typedef struct __TIME_SERVER_STRUCTURE__ {
	Big TS_Secret_Key;
	G1	TS_Public_Key; //Q = sP
	char t[TIME_LEN];
	G2 Ts;
	GT sd;
	Big rs;
	char Flag = TRUE; //Time server authentication passed in all cases 
}_TIME_SERVER_;

void Client_Read_File(_CLIENT_* Client);
void Server_Write_File(_SERVER_* Server);


void Print_char(char* src, int len);
void Copy_char(char* dst, char* src, int len);
void Hash_Function_using_SHA_256(char* src, int src_len, char* digest);
void Generating_key_using_256_digest(char* dst, int src_len, char* digest);
void XOR_two_char_using_CBC(char* src, char* dst, int len);
void Client_Encryption_using_AES_128_CBC(char* src, int src_len, char* dst, char* key);
void Client_Encryption_LC_using_AES_128_CBC(char* src, int src_len, char* dst, char* key);
void Client_Check_TagC_in_DB(_CLIENT_* Client, _SERVER_* Server);
void Server_add_Client_to_UIDC(char DB_UIDC[DB_Range][HASH_DIGEST_BYTE], char* Client_Name, char* Clt_num);
void Server_LC_Decryption_using_AES_128_CBC(char* src, int src_len, char* dst, char* key);
void Server_Tag_Verification(char* src1, char* src2,int len ,char* tag_flag);
void Initialize_Time_Server(_TIME_SERVER_* Time_Server);

void Step_1_Client_generates_k_C_TagC(_CLIENT_* Client);
void Step_2_Client_check_to_Server_TacC(_CLIENT_* Client, _SERVER_* Server);
void Step_3_Client_generates_sd_pairing(_CLIENT_* Client, _SERVER_* Server, _TIME_SERVER_* Time_Server);
void Step_4_Server_Verifiy_Server_TacC(_CLIENT_* Client, _SERVER_* Server, _TIME_SERVER_* Time_Server);

