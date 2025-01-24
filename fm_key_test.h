/*
 * fm_key_test.h
 *
 *  Created on: 2022年11月27日
 *      Author: xsluck
 */

#ifndef FM_KEY_TEST_H
#define FM_KEY_TEST_H

#include "fm_def.h"
#include "fm_sic_pub.h"

// 错误码定义
#define FME_FAIL 0xFFFF

// 全局变量声明
extern FM_HANDLE hDev;
extern FM_ECC_PublicKey lastPubKey;
extern FM_HKEY lastKeyHandle;
extern int hasKey;

// 函数声明
int GetDev(FM_S8 *keySerial);
int OpenDev(FM_U8 *keySerial);
int CloseDev();
int DevAdminLogin();
int DevOperLogin();
int DevUserLogout();
int GenRandom(FM_U32 u32Len, FM_U8 *pu8Random);
int GenECCKeypair();
int RunTest();
int AddUserKey();
int signVerifyTest(const FM_U8 *data, FM_U32 dataLen, FM_U8 *signature, FM_U32 *signLen, FM_HKEY hKey);
int delEccKey(FM_HKEY hkey);

#endif // FM_KEY_TEST_H
