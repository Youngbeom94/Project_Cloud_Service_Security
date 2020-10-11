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



void Print_char(char* src, int len);
void Hash_Function_using_SHA_256(char* src, int src_len, char* digest);
void Generating_key_using_256_digest(char* drc, int src_len, char* digest);
void XOR_two_char_using_CBC(char* src, char* drc, int len);
void Client_Encryption_using_AES_128_CBC(char* src, int src_len, char* drc, char* key);