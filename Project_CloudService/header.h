#pragma once

#include <iostream>
#include <ctime>
#include <stdlib.h>
#include <time.h>;
#include "zzn.h"
#include "miracl.h"
#include "big.h"
#include "ecn.h"


#define MR_PAIRING_BN    // AES-128 or AES-192 security
#include "pairing_3.h"



#define AES_SECURITY 128
#define _CRT_SECURE_NO_WARNINGS 
#define PT_LEN 16
#define CLIENT_FILE_LEN 30
#define CLIENT_FILE_LEN_PADDING ((16-(CLIENT_FILE_LEN%16)) + CLIENT_FILE_LEN)
#define HASH_DIGEST_BYTE 32
#define EXTRACT_RANDOMLEN 32
#define TIME_FLAG TRUE

#define TRUE 1
#define FALSE 0

typedef struct __CLIENT_STRUCTURE__ {
	char name[10] = "Alice";
	char Pt_Client_File[CLIENT_FILE_LEN] = { 0x00,0x00 };
	char Ct_Client_File[CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char Client_File_key[16] = { 0x00 };
	char Client_Tag[HASH_DIGEST_BYTE] = { 0x00 };

	char t[9] = "20201012";
	char Flag = TRUE; //Time server authentication passed in all cases 
	char ht[HASH_DIGEST_BYTE] = { 0x00 };
	Big r;
	G1 rP; //R = rP
}_CLIENT_;


typedef struct __SERVER_STRUCTURE__ {
	// DB Part
	char DB_TagC[HASH_DIGEST_BYTE] = { 0x00,0x00 };
	char DB_Ct_Client_File[CLIENT_FILE_LEN_PADDING] = { 0x00, };
	char DB_UIDC[10][HASH_DIGEST_BYTE] = { 0x00 };

	//DBL Part
	char t[9] = "20201012";
	G1 R; //R = rP
	char DBL_TagC[HASH_DIGEST_BYTE] = { 0x00,0x00 };
	char DBL_LC[CLIENT_FILE_LEN_PADDING] = { 0x00,0x00 };
	char DB_UIDC[10][HASH_DIGEST_BYTE] = { 0x00 };
	char Flag = TRUE; //Time server authentication passed in all cases 
}_SERVER_;

void Print_char(char* src, int len);
void Hash_Function_using_SHA_256(char* src, int src_len, char* digest);
void Generating_key_using_256_digest(char* drc, int src_len, char* digest);
void XOR_two_char_using_CBC(char* src, char* drc, int len);
void Client_Encryption_using_AES_128_CBC(char* src, int src_len, char* drc, char* key);