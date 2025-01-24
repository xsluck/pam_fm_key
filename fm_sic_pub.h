/******************************************************************************
 * Copyright (c) 2007, Shandong Fisherman Information Technology Co., Ltd.
 * All rights reserved.
 * 文件名称: fm_sic_pub.h
 * 文件描述: 渔翁智能密码钥匙SIC公共函数接口
 * 当前版本: 1.0
 * 作    者: LJ
 * 创建时间: 2007-01-07
 * 修改记录:
 * ----------------------------------------------
 *    时间    作者     描述
 ******************************************************************************/
#ifndef FM_SIC_PUB_H
#define FM_SIC_PUB_H

#include "fm_def.h"

#ifdef  __cplusplus
    extern "C" {
#endif
#define FM_OPEN_SEREL		  0x00000040  //是否以序列号形式打开设备
#define FM_OPEN_DEVID		  0x00000080  //是否以设备名形式打开设备

#define FM_INFO_SETDEVID    0x0105
#define FM_DEV_ID_LEN       64
#define FM_DEV_SER_LEN		16

//--cert---------------------
#define FM_CONT_RSA     1
#define FM_CONT_ECC     2

#define FM_CERT_ENC    1
#define FM_CERT_SIGN   2
#define FM_KEYNUM_ENC  3
#define FM_KEYNUM_SIGN 4
#define FM_CONT_TYPE   5
/************************ 文件系统 ************************/
// 最大的文件名长度
#define SIC_FILE_NAME_LEN       4
// 最大路径深度 \root\abcd\ef\gab\hijk，上述深度为5
#define SIC_FILE_DEPTH          16
// 最大目录的深度是路径深度减1
#define SIC_FILE_DIRDEPTH       (SIC_FILE_DEPTH-1)
// 最大路径长度
#define SIC_FILE_MAXPATH        ((SIC_FILE_NAME_LEN+1)*SIC_FILE_DEPTH)
// 文件空间大小
#define SIC_FILE_MAXSIZE        (128 * 1024)
#define SIC_FILE_MAXSIZE_TF     (640 * 1024)
#define SIC_FILE_MAXSIZE_TF3302     (192 * 1024)

// 文件信息结构
typedef struct tagFileInfoSt {
	FM_S8 as8FileName[SIC_FILE_NAME_LEN];
	FM_U32 u32FileSize;
	FM_U32 u32FileID;
} SIC_FILE_INFO, *PSIC_FILE_INFO;

/* 计数器 */
typedef struct tag_KeyCount_St {
	FM_U8 au8CountData[16];
	FM_U32 u32CountNum;
} KEYCOUNT;

/************************ 用户管理 ************************/
// 用户身份
#define CPC_USER_ADMIN          1   /* 管理员 */
#define CPC_USER_OPER           2   /* 操作员 */
// 用户数目
#define CPC_USER_MAXADMIN       5   /* 最多管理员数目 */
#define CPC_USER_MAXOPER        5   /* 最多操作员数目 */
#define CPC_USER_MAXUSER        (CPC_USER_MAXADMIN + CPC_USER_MAXOPER) /* 最多用户数 */
// 用户管理
#define CPC_USER_ADDADMIN       1   /* 添加管理员 */
#define CPC_USER_ADDOPER        2   /* 添加操作员 */
#define CPC_USER_DELADMIN       3   /* 删除管理员 */
#define CPC_USER_DELOPER        4   /* 删除操作员 */
// 用户备份管理
#define CPC_USER_BAK            1   /* 备份 */
#define CPC_USER_RES            2   /* 恢复 */
#define CPC_USER_BAKINIT        3   /* 备份初始化 */
#define CPC_USER_RESINIT        4   /* 恢复初始化 */
// 认证状态
#define CPC_USER_AUTHPASS       1   /* 认证通过 */
#define CPC_USER_AUTHNOPASS     0   /* 认证未通过 */

typedef struct tagUserInfoSt {
	FM_U8 au8Serial[FM_DEVINFO_SERIAL_LEN];     // 序列号
	FM_U8 u8Flag;                      // 本卡身份 CPC_USER_ADMIN / CPC_USER_OPER */
	FM_U8 u8IsAuthed;                           // 是否登录     1已登录
	FM_U8 u8Reserve1;                           // 保留
	FM_U8 u8Reserve2;                           // 保留
	FM_ECC_PublicKey ECCPublicKey;
} CPC_USER_INFO, *PCPC_USER_INFO;

/****************************备份需要的公开结构********************************/
// 备份类型
#define CPC_BK_TYPE_ALL     1   // 备份所有内容
#define CPC_BK_TYPE_FILEALL 2   // 备份文件系统
#define CPC_BK_TYPE_WKALL   3   // 备份所有工作密钥
#define CPC_BK_TYPE_RSAALL  4   // 备份所有RSA密钥
#define CPC_BK_TYPE_ECCALL  5   // 备份所有ECC密钥

// 备份信息存储的设备类型
#define CPC_BK_STORE_HOST   1    // 备份信息存储在主机文件
#define CPC_BK_STORE_DEVKEY 2    // 备份信息存储在设备所属的IC卡或者USBKey 暂不支持

// 备份管理初始化时的配置结构
typedef struct stBkConifg {
	FM_U32 u32Type;               // 备份类型
	FM_U32 u32StoreDev;           // 保留
	FM_U8 u8StoreFile[128];      // 备份信息存储的文件名
	FM_U32 u32ThresholdKeyID;     // 主密钥(门限密钥)ID [0-99]
	FM_U32 u32HKey;               // 保留
	FM_U8 u8FullPath[128];       // 保留
	FM_U32 u32Resvered[16];       // 保留
} CPC_BK_CONFIG, *PCPC_BK_CONFIG;

/****************************** API 函数定义 *********************************/
FM_RET __attribute__((__stdcall__)) FM_SIC_ReDownLoad(
FM_I FM_HANDLE hDev);

FM_RET __attribute__((__stdcall__)) FM_SIC_OpenDeviceEx(
FM_I FM_U8 *pu8Id,
FM_O FM_HANDLE *phDev);

FM_RET __attribute__((__stdcall__)) FM_SIC_InitSeril(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32BufLen,
FM_I FM_U8 *pu8Buf);

FM_RET __attribute__((__stdcall__)) FM_SIC_SetPackageName(
FM_I FM_U8 *pu8Package);

FM_RET __attribute__((__stdcall__)) FM_SIC_OpenDevice(
FM_I FM_U8 *pu8Id,
FM_I FM_U32 u32Type,
FM_I FM_U32 u32Flag,
FM_O FM_HANDLE *phDev);

FM_RET __attribute__((__stdcall__)) FM_SIC_OpenDevice2(
FM_I FM_U8 *pu8Id,
FM_I FM_U32 u32Type,
FM_I FM_U32 u32Flag,
FM_O FM_HANDLE *phDev,
FM_I FM_U32 u32fd,
FM_I FM_U8 *pu8DevPath);
FM_RET __attribute__((__stdcall__)) FM_SIC_CloseDeviceEx(
FM_I FM_HANDLE hDev);

FM_RET __attribute__((__stdcall__)) FM_SIC_CloseDevice(
FM_I FM_HANDLE hDev);

FM_RET __attribute__((__stdcall__)) FM_SIC_CloseAllDevice(
FM_I FM_HANDLE hDev);

FM_RET __attribute__((__stdcall__)) FM_SIC_GetDeviceInfo(
FM_I FM_HANDLE hDev, FM_O FM_DEV_INFO *pDevInfo);

FM_RET __attribute__((__stdcall__)) FM_SIC_GetDevType(
FM_I FM_HANDLE hDev,
FM_O FM_U32 *pu32DevType);

FM_RET __attribute__((__stdcall__)) FM_SIC_GenRandom(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Len,
FM_O FM_U8 *pu8Random);

FM_RET __attribute__((__stdcall__)) FM_SIC_GetInfo(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Flag,
FM_B FM_U32 *pu32Len,
FM_O FM_U8 *pu8OutBuf);

FM_RET __attribute__((__stdcall__)) FM_SIC_GetErrInfo(
FM_I FM_U32 u32LanFlag,
FM_I FM_U32 u32ErrCode,
FM_B FM_U32 *pu32Len,
FM_O FM_S8 *ps8Info);

FM_RET __attribute__((__stdcall__)) FM_SIC_OpenByName(
FM_I FM_U8 *pu8Id,
FM_I FM_U32 u32Type,
FM_I FM_U8 u8DevIndex,
FM_O FM_HANDLE *phDev);

FM_RET __attribute__((__stdcall__)) FM_SIC_OpenBySerial(
FM_I FM_U8 *pu8Id,
FM_I FM_U32 u32Type,
FM_I FM_U8 u8DevIndex,
FM_O FM_HANDLE *phDev);

FM_RET __attribute__((__stdcall__)) FM_SIC_EnumDevice(
FM_I FM_U32 u32EnumType,
FM_O FM_U8 *pu8ResultBuf,
FM_B FM_U32 *u32ResultBufLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_EnumDeviceSerialNum(
FM_O FM_U8 *pu8ResultBuf,
FM_B FM_U32 *u32ResultBufLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_GenRSAKeypair(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32KeyBits,
FM_B FM_HKEY *phKey, FM_O FM_RSA_PublicKey *pPubkey,
		FM_O FM_RSA_PrivateKey *pPrikey);

FM_RET __attribute__((__stdcall__)) FM_SIC_DelRSAKeypair(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey);

FM_RET __attribute__((__stdcall__)) FM_SIC_ImportRSAKeypair(
FM_I FM_HANDLE hDev,
FM_B FM_HKEY *phKey, FM_I FM_RSA_PublicKey *pPubkey,
		FM_I FM_RSA_PrivateKey *pPrikey);

FM_RET __attribute__((__stdcall__)) FM_SIC_ExportRSAKeypair(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey, FM_O FM_RSA_PublicKey *pPubkey,
		FM_O FM_RSA_PrivateKey *pPrikey);
FM_RET __attribute__((__stdcall__)) FM_SIC_RSAEncrypt(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen,
FM_O FM_U8 *pu8OutBuf,
FM_O FM_U32 *pu32OutLen, FM_I FM_RSA_PublicKey *pPubkey);

FM_RET __attribute__((__stdcall__)) FM_SIC_RSADecrypt(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen,
FM_O FM_U8 *pu8OutBuf,
FM_O FM_U32 *pu32OutLen, FM_I FM_RSA_PrivateKey *pPrikey);

FM_RET __attribute__((__stdcall__)) FM_SIC_RSASign(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey,
FM_I FM_U32 u32Alg,
FM_I FM_U8 *pu8DataBuf,
FM_I FM_U32 u32DataLen,
FM_O FM_U8 *pu8SignBuf,
FM_O FM_U32 *pu32SignLen, FM_I FM_RSA_PrivateKey *pPrikey);

FM_RET __attribute__((__stdcall__)) FM_SIC_RSAVerify(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey,
FM_I FM_U32 u32Alg,
FM_I FM_U8 *pu8DataBuf,
FM_I FM_U32 u32DataLen,
FM_I FM_U8 *pu8SignBuf,
FM_I FM_U32 u32SignLen, FM_I FM_RSA_PublicKey *pPubkey);

FM_RET __attribute__((__stdcall__)) FM_SIC_GenECCKeypair(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_B FM_HKEY *phKey, FM_O FM_ECC_PublicKey *pPubkey,
		FM_O FM_ECC_PrivateKey *pPrikey);

FM_RET __attribute__((__stdcall__)) FM_SIC_DelECCKeypair(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey);

FM_RET __attribute__((__stdcall__)) FM_SIC_ImportECCKeypair(
FM_I FM_HANDLE hDev,
FM_B FM_HKEY *phKey, FM_I FM_ECC_PublicKey *pPubkey,
		FM_I FM_ECC_PrivateKey *pPrikey);

FM_RET __attribute__((__stdcall__)) FM_SIC_ExportECCKeypair(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey, FM_O FM_ECC_PublicKey *pPubkey,
		FM_O FM_ECC_PrivateKey *pPrikey);

FM_RET __attribute__((__stdcall__)) FM_SIC_ECCEncrypt(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_HKEY hKey,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen, FM_I FM_ECC_PublicKey *pPubkey,
		FM_O FM_ECC_Cipher *pECCCipher);

FM_RET __attribute__((__stdcall__)) FM_SIC_ECCDecrypt(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_HKEY hKey, FM_I FM_ECC_Cipher *pECCCipher,
		FM_I FM_ECC_PrivateKey *pPrikey,
		FM_O FM_U8 *pu8OutBuf,
		FM_O FM_U32 *pu32OutLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_ECCSign(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_HKEY hKey,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen, FM_I FM_ECC_PrivateKey *pPrikey,
		FM_O FM_ECC_Signature *pSignature);

FM_RET __attribute__((__stdcall__)) FM_SIC_ECCVerify(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_HKEY hKey, FM_I FM_ECC_PublicKey *pPubkey,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen, FM_I FM_ECC_Signature *pSignature);

FM_RET __attribute__((__stdcall__)) FM_SIC_GenerateAgreementDataWithECC(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_HKEY hKey,
FM_I FM_U32 u32KeyBits,
FM_I FM_U8 *pu8SponsorID,
FM_I FM_U32 u32SponsorIDLen, FM_O FM_ECC_PublicKey *pSponsorPubKey,
		FM_O FM_ECC_PublicKey *pSponsorTmpPubKey,
		FM_O FM_HANDLE *phAgreementHandle);

FM_RET __attribute__((__stdcall__)) FM_SIC_GenerateAgreementDataAndKeyWithECC(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_HKEY hKey,
FM_I FM_U32 u32KeyBits,
FM_I FM_U8 *pu8ResponseID,
FM_I FM_U32 u32ResponseIDLen,
FM_I FM_U8 *pu8SponsorID,
FM_I FM_U32 u32SponsorIDLen, FM_I FM_ECC_PublicKey *pSponsorPubKey,
		FM_I FM_ECC_PublicKey *pSponsorTmpPubKey,
		FM_O FM_ECC_PublicKey *pResponsePubKey,
		FM_O FM_ECC_PublicKey *pResponseTmpPubKey,
		FM_O FM_HKEY *phKeyHandle);

FM_RET __attribute__((__stdcall__)) FM_SIC_GenerateKeyWithECC(
FM_I FM_HANDLE hDev,
FM_I FM_U8 *pu8ResponseID,
FM_I FM_U32 u32ResponseIDLen, FM_I FM_ECC_PublicKey *pResponsePubKey,
		FM_I FM_ECC_PublicKey *pResponseTmpPubKey,
		FM_I FM_HANDLE hAgreementHandle,
		FM_O FM_HKEY *phKeyHandle);

FM_RET __attribute__((__stdcall__)) FM_SIC_GenKey(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_U32 u32InLen,
FM_B FM_HKEY *phKey,
FM_O FM_U8 *pu8Key);

FM_RET __attribute__((__stdcall__)) FM_SIC_DelKey(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey);

FM_RET __attribute__((__stdcall__)) FM_SIC_ImportKey(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_U8 *pu8Key,
FM_I FM_U32 u32KeyLen,
FM_B FM_HKEY *phKey);

FM_RET __attribute__((__stdcall__)) FM_SIC_ExportKey(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey,
FM_O FM_U8 *pu8Key,
FM_B FM_U32 *pu32Len);

FM_RET __attribute__((__stdcall__)) FM_SIC_EncryptInit(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey,
FM_I FM_U32 u32Alg,
FM_I FM_U32 u32WorkMode,
FM_I FM_U8 *pu8Key,
FM_I FM_U32 u32KeyLen,
FM_I FM_U8 *pu8IV,
FM_I FM_U32 u32IVLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_EncryptUpdate(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen,
FM_O FM_U8 *pu8OutBuf,
FM_O FM_U32 *pu32OutLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_EncryptFinal(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg);

FM_RET __attribute__((__stdcall__)) FM_SIC_Encrypt(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey,
FM_I FM_U32 u32Alg,
FM_I FM_U32 u32WorkMode,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen,
FM_O FM_U8 *pu8OutBuf,
FM_O FM_U32 *pu32OutLen,
FM_I FM_U8 *pu8Key,
FM_I FM_U32 u32KeyLen,
FM_I FM_U8 *pu8IV,
FM_I FM_U32 u32IVLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_DecryptInit(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey,
FM_I FM_U32 u32Alg,
FM_I FM_U32 u32WorkMode,
FM_I FM_U8 *pu8Key,
FM_I FM_U32 u32KeyLen,
FM_I FM_U8 *pu8IV,
FM_I FM_U32 u32IVLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_DecryptUpdate(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen,
FM_O FM_U8 *pu8OutBuf,
FM_O FM_U32 *pu32OutLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_DecryptFinal(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg);

FM_RET __attribute__((__stdcall__)) FM_SIC_Decrypt(
FM_I FM_HANDLE hDev,
FM_I FM_HKEY hKey,
FM_I FM_U32 u32Alg,
FM_I FM_U32 u32WorkMode,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen,
FM_O FM_U8 *pu8OutBuf,
FM_O FM_U32 *pu32OutLen,
FM_I FM_U8 *pu8Key,
FM_I FM_U32 u32KeyLen,
FM_I FM_U8 *pu8IV,
FM_I FM_U32 u32IVLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_HashInit(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_U8 *pu8IV,
FM_I FM_U32 u32IVLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_HashUpdate(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_HashFinal(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_O FM_U8 *pu8OutMACBuf,
FM_B FM_U32 *pu32OutMACLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_SM3Init(
FM_I FM_HANDLE hDev, FM_I FM_ECC_PublicKey *pPubkey,
FM_I FM_U8 *pu8ID,
FM_I FM_U32 u32IDLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_SM3Update(
FM_I FM_HANDLE hDev,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_SM3Final(
FM_I FM_HANDLE hDev,
FM_O FM_U8 *pu8HashBuf,
FM_B FM_U32 *pu32HashLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_HashInit_Hard(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_U8 *pu8IV,
FM_I FM_U32 u32IVLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_HashUpdate_Hard(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_HashFinal_Hard(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Alg,
FM_O FM_U8 *pu8OutMACBuf,
FM_B FM_U32 *pu32OutMACLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_SM3Init_Hard(
FM_I FM_HANDLE hDev, FM_I FM_ECC_PublicKey *pPubkey,
FM_I FM_U8 *pu8ID,
FM_I FM_U32 u32IDLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_SM3Update_Hard(
FM_I FM_HANDLE hDev,
FM_I FM_U8 *pu8InBuf,
FM_I FM_U32 u32InLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_SM3Final_Hard(
FM_I FM_HANDLE hDev,
FM_O FM_U8 *pu8HashBuf,
FM_B FM_U32 *pu32HashLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_USER_Login(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Type,
FM_I FM_U8 *pu8PinBuf,
FM_I FM_U32 u32PinLen,
FM_O FM_HUSER *phUser,
FM_O FM_U32 *pu32RetryNum);

FM_RET __attribute__((__stdcall__)) FM_SIC_USER_Logout(
FM_I FM_HANDLE hDev,
FM_I FM_HUSER hUser);

FM_RET __attribute__((__stdcall__)) FM_SIC_USER_ChangePin(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Flag,
FM_I FM_U8 *pu8OldPinBuf,
FM_I FM_U32 u32OldPinLen,
FM_I FM_U8 *pu8NewPinBuf,
FM_I FM_U32 u32NewPinLen,
FM_O FM_U32 *pu32RetryNum);

FM_RET __attribute__((__stdcall__)) FM_SIC_IntAuthenticate(
FM_I FM_HANDLE hDev,
FM_I FM_U8 *pu8Random,
FM_I FM_U32 u32RndLen,
FM_O FM_U8 *pu8Encrypt,
FM_O FM_U32 *pu32EncLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_ExtAuthenticate(
FM_I FM_HANDLE hDev,
FM_I FM_U8 *pu8Encrypt,
FM_I FM_U32 u32EncLen,
FM_O FM_U32 *pu32RetryNum);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_Init(
FM_I FM_HANDLE hDev);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_CreateDir(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8FullDir,
FM_I FM_U32 u32AccCond);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_DeleteDir(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8FullDir);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_CreateFile(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8DirName,
FM_I FM_S8 *ps8FileName,
FM_I FM_U32 u32FileSize,
FM_I FM_U32 u32AccCond);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_ReadFile(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8DirName,
FM_I FM_S8 *ps8FileName,
FM_I FM_U32 u32Offset,
FM_I FM_U32 u32Size,
FM_O FM_U8 *pu8Buf);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_WriteFile(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8DirName,
FM_I FM_S8 *ps8FileName,
FM_I FM_U32 u32Offset,
FM_I FM_U32 u32Size,
FM_I FM_U8 *pu8Buf);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_DeleteFile(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8DirName,
FM_I FM_S8 *ps8FileName);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_EnmuDir(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8DirName,
FM_B FM_U32 *pu32BufLen,
FM_O FM_U8 *pu8Buf,
FM_O FM_U32 *pu32DirNum);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_EnmuFile(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8DirName,
FM_B FM_U32 *pu32BufLen,
FM_O FM_U8 *pu8Buf,
FM_O FM_U32 *pu32FileNum);

FM_RET __attribute__((__stdcall__)) FM_SIC_Cmd(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Cmd,
FM_I FM_U32 aPara[],
FM_I FM_U8 *pu8InData,
FM_I FM_U32 u32InLen,
FM_O FM_U8 *pu8OutData,
FM_B FM_U32 *pu32OutLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_ReadHiddenPart(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Offset,
FM_I FM_U32 u32Size,
FM_O FM_VOID *pOutBuff,
FM_I FM_U32 u32BufLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_WriteHiddenPart(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Offset,
FM_I FM_U32 u32Size,
FM_I FM_VOID *pOutBuff,
FM_I FM_U32 u32BufLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_FILE_GetInfo(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8DirName,
FM_I FM_S8 *ps8FileName, FM_O SIC_FILE_INFO *pFileInfo);

FM_RET __attribute__((__stdcall__)) FM_SIC_WaitForEvent(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Flag,
FM_I FM_VOID *pfunc,
FM_I FM_VOID *pPara);

FM_RET __attribute__((__stdcall__)) FM_RSA_PKCS1_padding_add_type_1(FM_U8 *to,
		FM_U32 tlen,
		FM_U8 *from, FM_U32 flen);

FM_RET __attribute__((__stdcall__)) FM_RSA_PKCS1_padding_check_type_1(FM_U8 *to,
		FM_U32 tlen,
		FM_U8 *from, FM_U32 flen);

FM_RET __attribute__((__stdcall__)) FM_RSA_PKCS1_padding_add_type_2(FM_U8 *to,
		FM_U32 tlen,
		FM_U8 *from, FM_U32 flen);

FM_RET __attribute__((__stdcall__)) FM_RSA_PKCS1_padding_check_type_2(FM_U8 *to,
		FM_U32 tlen,
		FM_U8 *from, FM_U32 flen);

FM_RET __attribute__((__stdcall__)) FM_SIC_ContainerWriteECCCert(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Flag,
FM_I FM_S8 *ps8ContainerName,
FM_I FM_U8 *pu8Data,
FM_I FM_U32 u32DataLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_ContainerWrite(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Flag,
FM_I FM_S8 *ps8ContainerName,
FM_I FM_U8 *pu8Data,
FM_I FM_U32 u32DataLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_ContainerRead(
FM_I FM_HANDLE hDev,
FM_I FM_U32 u32Flag,
FM_I FM_S8 *ps8ContainerName,
FM_O FM_U8 *pu8Data,
FM_O FM_U32 *pu32DataLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_ContainerDelete(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8ContainerName);

FM_RET __attribute__((__stdcall__)) FM_SIC_ContainerEnum(
FM_I FM_HANDLE hDev,
FM_O FM_S8 *ps8ContainerNames,
FM_O FM_U32 *pu32ContainerNamesLen);

FM_RET __attribute__((__stdcall__)) FM_SIC_ContainerInfo(
FM_I FM_HANDLE hDev,
FM_I FM_S8 *ps8ContainerName,
FM_O FM_U32 *pu32ContainerType);

#ifdef FMCFG_OS_WINDOWS
FM_RET __attribute__((__stdcall__)) FM_SIC_ImportP12Cert
(
		FM_I FM_HANDLE hDev,
		FM_I FM_U8 *pu8CertData,
		FM_I FM_U32 u32CertDataLen,
		FM_I FM_U8 *pu8Pin,
		FM_I FM_U32 u32PinLen,
		FM_I FM_S8 *ps8ContainerName,
		FM_I FM_U32 u32CertType,
		FM_B FM_HKEY *phKeyID
);
#endif

FM_RET __attribute__((__stdcall__)) FM_SIC_ImportRSAPrivateKey(
FM_I FM_HANDLE hDev,
FM_I FM_U32 AsymFlag,
FM_I FM_U8 *pu8Symbuf,
FM_I FM_U32 SymFlag,
FM_I FM_U32 WorkMode,
FM_I FM_U8 *pu8IV,
FM_I FM_U8 *pu8Asymbuf,
FM_I FM_U32 AsymKeyCryptNum,
FM_I FM_U32 AsymKeyStorNum);

FM_RET __attribute__((__stdcall__)) FM_SIC_ImportECCPrivateKey(
FM_I FM_HANDLE hDev,
FM_I FM_U8 *pu8Symbuf,
FM_I FM_U32 SymFlag,
FM_I FM_U32 WorkMode,
FM_I FM_U8 *pu8IV,
FM_I FM_U8 *pu8Asymbuf,
FM_I FM_U32 AsymKeyCryptNum,
FM_I FM_U32 AsymKeyStorNum);

FM_RET __attribute__((__stdcall__)) FM_SIC_DevReset(
FM_I FM_HANDLE hDev);

#ifdef  __cplusplus
    }
#endif  /* #ifdef  __cplusplus */

#endif  /* #ifndef FM_SIC_PUB_H */

