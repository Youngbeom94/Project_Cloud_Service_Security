#pragma once
#define _CRT_SECURE_NO_WARNINGS 

#include <iostream>
#include <fstream>
#include <ctime>
#include <stdlib.h>
#include <time.h>
#include<assert.h>
#include "zzn.h"
#include "miracl.h"
#include "big.h"
#include "ecn.h"

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#include "pairing_3.h"
#include <iomanip>
#include <process.h>
#include <Windows.h>


#define AES_SECURITY 128
#define AES_KEY_LEN 16
#define CLIENT_FILE_LEN 38
#define CLIENT_FILE_LEN_PADDING ((16-(CLIENT_FILE_LEN%16)) + CLIENT_FILE_LEN)
#define HASH_DIGEST_BYTE 32
#define EXTRACT_RANDOMLEN 32
#define BNCURVE_POINTLEN 32
#define PT_LEN 16
#define TIME_SERVER_BUFF 10
#define TIME_SERVER_BUFF_SERVER 60
//#define TIME_LEN 15 // if test version, it should be 15
#define TIME_LEN 9 // if it's not test version, it should be 9

#define Client_Name_Len 20
#define DB_Range 10
#define TRUE 0
#define FALSE 1
#define BAD 2

#define AES 1
#define LEA 2
#define SEED 3
#define XOR_based 4

#define SHA_256 1
#define SHA_512 2 
#define SHA_3	3

#define CLIENT_NUMBER 5
#define FILENAME_LEN 10

#define IPAD 0x36
#define OPAD 0x5c
#define HMAC_BLOCKBYTE 64

typedef struct __FILE_ELEMENT__ {
	char name[CLIENT_NUMBER][Client_Name_Len];
	char Pt_Client_File[CLIENT_NUMBER][CLIENT_FILE_LEN];
	char Ct_Client_File[CLIENT_NUMBER][CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char Ct_LC_File[CLIENT_NUMBER][CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char Client_File_key[CLIENT_NUMBER][AES_KEY_LEN] = { 0x00 };
	char Client_Tag[CLIENT_NUMBER][HASH_DIGEST_BYTE] = { 0x00 };

	char t[CLIENT_NUMBER][TIME_LEN] = {0x00}; // General case : check day
	//char t[TIME_LEN] = "20201105112050";// Test case : check sec
	int client_buff = -1;
	int current_client = -1;
	char Time_Flag = TRUE; //Time server authentication passed in all cases 
	char DB_Flag = -1;

}_FILE_ELEMENT_;


typedef struct __CLIENT_STRUCTURE__ {
	char name[Client_Name_Len] ;
	char Pt_Client_File[CLIENT_FILE_LEN];
	char Ct_Client_File[CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char Ct_LC_File[CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char Client_File_key[16] = { 0x00 };
	char Client_Tag[HASH_DIGEST_BYTE] = { 0x00 };

	char t[TIME_LEN] = {0x00}; // General case : check day
	//char t[TIME_LEN] = "20201105112050";// Test case : check sec
	char Time_Flag = TRUE; //Time server authentication passed in all cases 
	int File_NUM = 1;
	char DB_Flag = -1; 
	int Crypto_Flag = -1;
	int Hashing_Flag = -1;

	G1 rP; //R = rP
	G2 ht;
	GT sd; 
	Big r;
	Big rs;
}_CLIENT_;

typedef struct __SERVER_STRUCTURE__ {
	// DB Part
	char DB_TagC[DB_Range][HASH_DIGEST_BYTE] = { 0x00,0x00 };
	char DB_Ct_Client_File[DB_Range][CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char DB_UIDC[DB_Range][HASH_DIGEST_BYTE] = { 0x00 };
	char Client_Numeber = -1;
	char File_NUM = 0;

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
	int Crypto_Flag = -1;
	int Hashing_Flag = -1;

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
	char Server_Flag = FALSE;

}_TIME_SERVER_;

void Client_Read_File(_CLIENT_* Client, _FILE_ELEMENT_ * File);
void Add_File_Client_Num(_FILE_ELEMENT_* File, char* name);
void Server_Write_File(_SERVER_* Server);


void Print_char(char* src, int len);
void Copy_char(char* dst, char* src, int len);
void Hash_Function_using_SHA_256(char* src, int src_len, char* digest);
void Generating_key_using_fixed_digest(char* dst, int src_len, char* digest);
void XOR_two_char_using_CBC(char* src, char* dst, int len);
void Client_Encrypte_File(char* dst, char* src, char* key, int len, int Crypto_Flag);
void Client_Encrypte_C_to_LC(char* dst, char* src, char* key, int len, int Crypto_Flag);
void Client_Hashing_File(char* dst, char* src, int len, int Hashing_Flag);
void Client_Encryption_using_AES_128_CBC(char* src, int src_len, char* dst, char* key);
void Client_Encryption_LC_using_AES_128_CBC(char* src, int src_len, char* dst, char* key);
void Client_Check_TagC_in_DB(_CLIENT_* Client, _SERVER_* Server, _FILE_ELEMENT_* File);
void Server_Hashing_File_to_Tag(char* dst, char* src, int len, int Hashing_Flag);
void Server_Decrypt_LC_to_C(char* dst, char* src, char* key, int len, int Crypto_Flag);
void Server_add_Client_to_UIDC(char DB_UIDC[DB_Range][HASH_DIGEST_BYTE], char* Client_Name, char* Clt_num);
void Server_LC_Decryption_using_AES_128_CBC(char* src, int src_len, char* dst, char* key);
void Server_Tag_Verification(char* src1, char* src2,int len ,char* tag_flag);
int	char_compare(char* src1, char* src2, int len);

void Initialize_Time_Server(_TIME_SERVER_* Time_Server);
DWORD WINAPI Initialize_Time_Server_min(void* data);
void Client_generates_K_C_TagC(_CLIENT_* Client, _FILE_ELEMENT_* File);
void Client_check_to_Server_TacC(_CLIENT_* Client, _SERVER_* Server, _FILE_ELEMENT_* File);
void Client_Generates_ht_R_LC_sd(_CLIENT_* Client, _SERVER_* Server, _TIME_SERVER_* Time_Server, _FILE_ELEMENT_* File);
void Server_Verifiy_TagC(_CLIENT_* Client, _SERVER_* Server, _TIME_SERVER_* Time_Server, _FILE_ELEMENT_* File);
void Server_Verifiy_TagC_min(_CLIENT_* Client, _SERVER_* Server, _TIME_SERVER_* Time_Server);


void Hash_MAC(char* src, int src_len, char* key, int key_len, char* mac);