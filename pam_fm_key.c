/*
 * pam_fm_key.c
 *
 *  Created on: 2022年11月27日
 *      Author: wangzhi
 */

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>

#include "fm_def.h"
#include "fm_sic_pub.h"

#define KEY_FILE "/etc/pam.d/upk.key"
#define MAX_LINE_LENGTH 1024
#define RANDOM_LENGTH 32

FM_HANDLE hDev;

// 从文件中查找用户对应的设备序列号和公钥
static int find_user_key_info(const char *username, char *keySerial, FM_ECC_PublicKey *pubKey) {
	FILE *fp;
	char line[MAX_LINE_LENGTH];
	char file_username[256];
	char file_serial[36];
	char pubkey_hex[130];  // 04 + 64字节X + 64字节Y
	
	fp = fopen(KEY_FILE, "r");
	if (fp == NULL) {
		return PAM_AUTH_ERR;
	}
	
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%[^:]:%[^:]:%s", file_username, file_serial, pubkey_hex) == 3) {
			if (strcmp(username, file_username) == 0) {
				// 找到匹配的用户
				strcpy(keySerial, file_serial);
				
				// 解析公钥(跳过"04"前缀)
				char *pos = pubkey_hex + 2;
				for (int i = 0; i < 32; i++) {
					sscanf(pos + i*2, "%02hhX", &pubKey->x[i]);
				}
				pos += 64;
				for (int i = 0; i < 32; i++) {
					sscanf(pos + i*2, "%02hhX", &pubKey->y[i]);
				}
				
				fclose(fp);
				return PAM_SUCCESS;
			}
		}
	}
	
	fclose(fp);
	return PAM_AUTH_ERR;
}

//认证管理,设置用户证书
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
		const char **argv) {
	return PAM_SUCCESS;
}

//账号管理
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
		const char **argv) {
	return PAM_SUCCESS;
}

//编写PAM SPI接口代码,由PAM API pam_authenticate通过dlopen方式调用
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
		const char **argv) {
	int ret;
	const char *username;
	char keySerial[36] = {0};
	FM_ECC_PublicKey pubKey;
	FM_U8 random[32];
	FM_ECC_Signature signature;
	FM_HKEY hKey;

	// 获取用户名
	ret = pam_get_user(pamh, &username, NULL);
	if (ret != PAM_SUCCESS) {
		syslog(LOG_ERR, "Failed to get username: %s", pam_strerror(pamh, ret));
		return PAM_AUTH_ERR;
	}
	syslog(LOG_INFO, "Verifying user: %s", username);

	// 1. 读取用户公钥信息
	FILE *fp = fopen("/etc/pam.d/upk.key", "r");
	if (fp == NULL) {
		syslog(LOG_ERR, "Failed to open key file: /etc/pam.d/upk.key");
		return PAM_AUTH_ERR;
	}

	char line[1024];
	int auth_success = 0;
	
	while (fgets(line, sizeof(line), fp)) {
		char fileUser[256];
		char fileSerial[36];
		int keyIndex;
		char pubKeyHex[130];
		
		if (sscanf(line, "%[^:]:%[^:]:%d:%s", fileUser, fileSerial, &keyIndex, pubKeyHex) == 4) {
			if (strcmp(fileUser, username) == 0) {
				strncpy(keySerial, fileSerial, sizeof(keySerial)-1);
				syslog(LOG_INFO, "Trying key record for user: %s -> %s, key index: %d", username, keySerial, keyIndex);
				
				// 解析公钥
				if (strlen(pubKeyHex) < 130) {
					syslog(LOG_ERR, "Public key format error for serial %s", keySerial);
					continue;
				}
				
				// 跳过"04"前缀
				char *ptr = pubKeyHex + 2;
				for (int i = 0; i < 32; i++) {
					sscanf(ptr + i*2, "%02hhX", &pubKey.x[i]);
				}
				ptr += 64;
				for (int i = 0; i < 32; i++) {
					sscanf(ptr + i*2, "%02hhX", &pubKey.y[i]);
				}
				pubKey.bits = 256;
				hKey = (FM_HKEY)(keyIndex & 0x7F);

				// 尝试打开设备
				ret = OpenDev((FM_U8*)keySerial);
				if (ret != FME_OK) {
					syslog(LOG_INFO, "Failed to open device %s: %03X", keySerial, ret);
					continue;
				}

				// 生成随机数
				ret = FM_SIC_GenRandom(hDev, sizeof(random), random);
				if (ret != FME_OK) {
					syslog(LOG_ERR, "Random number generation failed for %s: %03X", keySerial, ret);
					CloseDev();
					continue;
				}

				// 使用设备签名
				ret = FM_SIC_ECCSign(hDev, FM_ALG_SM2_1, hKey, random, sizeof(random), NULL, &signature);
				if (ret != FME_OK) {
					syslog(LOG_ERR, "Signature failed for %s: %03X", keySerial, ret);
					CloseDev();
					continue;
				}

				// 使用公钥验证签名
				ret = FM_SIC_ECCVerify(hDev, FM_ALG_SM2_1, FM_HKEY_FROM_HOST, &pubKey, random, sizeof(random), &signature);
				if (ret == FME_OK) {
					syslog(LOG_INFO, "Authentication successful with device %s", keySerial);
					CloseDev();
					auth_success = 1;
					break;
				}

				syslog(LOG_ERR, "Signature verification failed for %s: %03X", keySerial, ret);
				CloseDev();
			}
		}
	}
	
	fclose(fp);
	return auth_success ? PAM_SUCCESS : PAM_AUTH_ERR;
}

int OpenDev(FM_U8 *keySerial) {
	FM_U32 u32Ret = FME_OK;
	u32Ret = FM_SIC_OpenBySerial(keySerial, 0, 0, &hDev);
	if (u32Ret != FME_OK) {
		syslog(LOG_ERR,"\nOpen Device FAIL:%03X!\n", u32Ret);
		return u32Ret;
	}
	return FME_OK;
}
int CloseDev() {
	FM_U32 u32Ret = FM_SIC_CloseDevice(hDev);
	if (u32Ret != FME_OK) {
		syslog(LOG_ERR,"\nClose Device FAIL:%03X\n", u32Ret);
		return u32Ret;
	}
	return FME_OK;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

