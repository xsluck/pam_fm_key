#include "fm_key_test.h"

#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>

// 全局变量定义
FM_HANDLE hDev;
FM_ECC_PublicKey lastPubKey;
FM_HKEY lastKeyHandle;
int hasKey = 0;

int main(int argc, char *argv[])
{
	int choice;
	FM_S8 keySerial[36];
	int running = 1;

	printf("\n=== FM Key Test Program ===\n");

	while (running)
	{
		printf("\n一级菜单:\n");
		printf("1. 获取设备序列号\n");
		printf("2. 打开设备\n");
		printf("3. 关闭设备\n");
		printf("0. 退出程序\n");
		printf("请输入选项 (0-3): ");

		scanf("%d", &choice);

		switch (choice)
		{
		case 0:
			running = 0;
			printf("\n程序退出\n");
			break;
		case 1:
			GetDev(keySerial);
			break;
		case 2:
		{
			FM_S8 keySerial[36] = {0};
			FM_U8 pu8Id[300] = {0};
			FM_U32 u32len = sizeof(pu8Id);
			FM_U32 u32tempLen = FM_DEVINFO_SERIAL_LEN + 1;

			// 先获取设备列表
			int ret = GetDev(keySerial);
			if (ret != FME_OK)
			{
				break;
			}

			// 重新获取设备信息以便选择
			FM_U32 u32Ret = FM_SIC_EnumDevice(FM_OPEN_SEREL, pu8Id, &u32len);
			if (u32Ret != FME_OK)
			{
				printf("\n获取设备序列号失败:%03X\n", u32Ret);
				break;
			}

			FM_U32 deviceCount = u32len / u32tempLen;
			if (deviceCount == 0)
			{
				printf("\n未找到设备\n");
				break;
			}

			// 获取用户选择
			int choice;
			printf("\n请选择要打开的设备 (0-%d): ", deviceCount - 1);
			scanf("%d", &choice);

			if (choice < 0 || choice >= deviceCount)
			{
				printf("无效的设备索引\n");
				break;
			}

			// 获取选中设备的序列号
			memset(keySerial, 0, sizeof(keySerial));
			for (int j = 0; j < u32tempLen; j++)
			{
				keySerial[j] = pu8Id[j + choice * u32tempLen];
			}

			ret = OpenDev(keySerial);
			if (ret == FME_OK)
			{
				int subRunning = 1;
				while (subRunning)
				{
					printf("\n二级菜单:\n");
					printf("1. 管理员登录\n");
					printf("2. 操作员登录\n");
					printf("3. 生成ECC密钥对\n");
					printf("4. 生成随机数\n");
					printf("5. 用户登出\n");
					printf("6. 执行自动测试\n");
					printf("7. 添加用户密钥\n");
					printf("8. 删除ECC密钥对\n");
					printf("9. 签名验签测试\n");
					printf("10. 导出公钥\n");
					printf("11. 获取设备信息\n");
					printf("0. 返回上级菜单\n");
					printf("请输入选项 (0-11): ");

					int subChoice;
					scanf("%d", &subChoice);

					switch (subChoice)
					{
					case 0:
						subRunning = 0;
						CloseDev(); // 返回上级菜单时自动关闭设备
						break;
					case 1:
						DevAdminLogin();
						break;
					case 2:
						DevOperLogin();
						break;
					case 3:
						GenECCKeypair();
						break;
					case 4:
					{
						FM_U8 random[8] = {0};
						GenRandom(8, random);
						break;
					}
					case 5:
						DevUserLogout();
						break;
					case 6:
						RunTest();
						break;
					case 7:
						AddUserKey();
						break;
					case 8:
					{
						printf("请输入要删除的密钥索引(0-31): ");
						int keyIndex;
						scanf("%d", &keyIndex);

						if (keyIndex < 0 || keyIndex > 31)
						{
							printf("\n错误：密钥索引必须在0-31之间\n");
							break;
						}

						FM_HKEY hkey = (FM_HKEY)(keyIndex & 0x1F);
						int ret = delEccKey(hkey);
						if (ret != FME_OK)
						{
							printf("删除ECC密钥对失败\n");
						}
						else
						{
							printf("删除ECC密钥对成功\n");
						}
						break;
					}
					case 9:
					{
						printf("请输入要测试的密钥索引(0-31): ");
						int keyIndex;
						scanf("%d", &keyIndex);

						if (keyIndex < 0 || keyIndex > 31)
						{
							printf("\n错误：密钥索引必须在0-31之间\n");
							break;
						}

						unsigned char testData[] = "Test Data For Signature";
						unsigned char signature[64] = {0};
						FM_U32 signLen = sizeof(signature);
						int ret = signVerifyTest(testData, strlen((char *)testData), signature, &signLen, (FM_HKEY)(keyIndex & 0x1F));
						if (ret != FME_OK)
						{
							printf("签名验签失败\n");
							break;
						}
						printf("\n签名验签成功\n");
						break;
					}
					case 10:
					{
						printf("请输入要导出的密钥索引(0-31): ");
						int keyIndex;
						scanf("%d", &keyIndex);

						if (keyIndex < 0 || keyIndex > 31)
						{
							printf("\n错误：密钥索引必须在0-31之间\n");
							break;
						}

						FM_ECC_PublicKey publicKey;
						FM_HKEY hKey = (FM_HKEY)(keyIndex & 0x1F);
						int ret = exportPublicKey(hKey, &publicKey);
						if (ret != FME_OK)
						{
							printf("导出公钥失败");
							break;
						}
						printf("导出公钥成功:\n");
						printf("Public Key: 04"); // 04 前缀表示未压缩的公钥
						for (int i = 0; i < 32; i++)
						{
							printf("%02X", publicKey.x[i]);
						}
						for (int i = 0; i < 32; i++)
						{
							printf("%02X", publicKey.y[i]);
						}
						printf(" bits: %02X\n", publicKey.bits);
						break;
					}
					case 11:
						getDeviceInfo();
						break;
					default:
						printf("\n无效的选项，请重新选择\n");
						break;
					}
				}
			}
			break;
		}
		case 3:
			CloseDev();
			break;
		default:
			printf("\n无效的选项，请重新选择\n");
			break;
		}
	}

	return 0;
}
int GetDev(FM_S8 *keySerial)
{
	FM_U32 i = 0, j = 0;
	FM_U8 pu8Id[300] = {0};
	FM_U32 u32len = sizeof(pu8Id);
	FM_U32 u32tempLen = FM_DEVINFO_SERIAL_LEN + 1;
	FM_S8 strings[100] = {0};
	FM_U32 u32Ret = FM_SIC_EnumDevice(FM_OPEN_SEREL, pu8Id, &u32len);
	if (u32Ret != FME_OK)
	{
		printf("\n获取设备序列号失败:%03X\n", u32Ret);
		return u32Ret;
	}

	// 计算设备数量
	FM_U32 deviceCount = u32len / u32tempLen;
	if (deviceCount == 0)
	{
		printf("\n未找到设备\n");
		return FME_FAIL;
	}

	printf("\n发现 %d 个设备:\n", deviceCount);
	for (i = 0; i < deviceCount; i++)
	{
		memset(strings, 0, sizeof(strings));
		for (j = 0; j < u32tempLen; j++)
		{
			strings[j] = pu8Id[j + i * u32tempLen];
		}
		printf("%d %s\n", i, strings);

		// 如果是第一个设备，保存序列号到输出参数
		if (i == 0)
		{
			strcpy(keySerial, strings);
		}
	}

	return FME_OK;
}
int OpenDev(FM_U8 *keySerial)
{
	// 打开选中的设备
	FM_U32 u32Ret = FM_SIC_OpenBySerial(keySerial, 0, 0, &hDev);
	if (u32Ret != FME_OK)
	{
		printf("\n打开设备失败:%03X!\n", u32Ret);
		return u32Ret;
	}
	printf("\n成功打开设备: %s\n", keySerial);
	return FME_OK;
}
int CloseDev()
{
	FM_U32 u32Ret = FM_SIC_CloseDevice(hDev);
	if (u32Ret != FME_OK)
	{
		printf("\nClose Device FAIL:%03X\n", u32Ret);
		return u32Ret;
	}
	printf("\nClose Device OK\n");
	return FME_OK;
}
int DevAdminLogin()
{
	char pinBuf[32] = {0};
	printf("请输入管理员密码: ");
	scanf("%s", pinBuf);

	int u32PinLen = strlen(pinBuf);
	int pu32RetryNum = 0;
	FM_U32 u32Ret = FM_SIC_USER_Login(hDev, FM_PIN_ADMIN, (FM_U8 *)pinBuf, u32PinLen,
									  0, &pu32RetryNum);
	if (u32Ret != FME_OK)
	{
		printf("\n管理员登录失败:%03X,剩余重试次数:%02X\n", u32Ret,
			   pu32RetryNum);
		return u32Ret;
	}
	printf("\n管理员登录成功\n");
	return FME_OK;
}
int DevOperLogin()
{
	char pinBuf[32] = {0};
	printf("请输入操作员密码: ");
	scanf("%s", pinBuf);

	int u32PinLen = strlen(pinBuf);
	FM_U32 pu32RetryNum = 0;
	FM_U32 u32Ret = FM_SIC_USER_Login(hDev, FM_PIN_OPER, (FM_U8 *)pinBuf, u32PinLen,
									  0, &pu32RetryNum);
	if (u32Ret != FME_OK)
	{
		printf("\n操作员登录失败:%03X,剩余重试次数:%02X\n", u32Ret,
			   pu32RetryNum);
		return u32Ret;
	}
	printf("\n操作员登录成功\n");
	return FME_OK;
}
int DevUserLogout()
{
	FM_U32 u32Ret = FM_SIC_USER_Logout(hDev, 0);
	if (u32Ret != FME_OK)
	{
		printf("\nDevice User Logout FAIL:%03X\n", u32Ret);
		return u32Ret;
	}
	printf("\nDevice User Logout OK\n");
	return FME_OK;
}
int GenRandom(FM_U32 u32Len, FM_U8 *pu8Random)
{
	FM_U32 u32Ret = FM_SIC_GenRandom(hDev, u32Len, pu8Random);
	if (u32Ret != FME_OK)
	{
		printf("\nGen Random FAIL:%03X\n", u32Ret);
		return u32Ret;
	}

	printf("\nGen Random OK, HEX: ");
	for (FM_U32 i = 0; i < u32Len; i++)
	{
		printf("%02X", pu8Random[i]);
	}
	printf("\n");

	return FME_OK;
}
int GenECCKeypair()
{
	FM_HKEY hkey;
	static FM_ECC_PublicKey pPubkey;
	FM_ECC_PrivateKey pPrikey;

	printf("请输入密钥索引(0-31): ");
	int keyIndex;
	scanf("%d", &keyIndex);

	if (keyIndex < 0 || keyIndex > 31)
	{
		printf("\n错误：密钥索引必须在0-31之间\n");
		return FME_FAIL;
	}

	// 最高位设置为0表示永久存储，其他位为密钥索引
	hkey = (FM_HKEY)(keyIndex & 0x1F);
	FM_U32 u32Ret = FM_SIC_GenECCKeypair(hDev, FM_ALG_SM2_1, &hkey, &pPubkey,
										 &pPrikey);
	if (u32Ret != FME_OK)
	{
		printf("\nGen ECCKeypair FAIL:%03X\n", u32Ret);
		return u32Ret;
	}

	printf("\nGen ECCKeypair OK\n");
	printf("Public Key: 04"); // 04 前缀表示未压缩的公钥
	for (int i = 0; i < 32; i++)
	{
		printf("%02X", pPubkey.x[i]);
	}
	for (int i = 0; i < 32; i++)
	{
		printf("%02X", pPubkey.y[i]);
	}
	printf("\n");

	printf("Private Key: ");
	// 跳过前8位无用数据
	for (int i = 4; i < sizeof(pPrikey); i++)
	{
		printf("%02X", ((unsigned char *)&pPrikey)[i]);
	}
	printf("\n");

	return FME_OK;
}
int signVerifyTest(const FM_U8 *data, FM_U32 dataLen, FM_U8 *signature, FM_U32 *signLen, FM_HKEY hKey)
{
	int ret;
	FM_ECC_Signature eccSignature = {0};
	FM_ECC_PublicKey publicKey;

	if (data == NULL || signature == NULL || signLen == NULL)
	{
		printf("Invalid parameters\n");
		return FME_FAIL;
	}

	ret = FM_SIC_ECCSign(hDev, FM_ALG_SM2_1, hKey, (FM_U8 *)data, dataLen, NULL, &eccSignature);
	if (ret != FME_OK)
	{
		printf("ECCSign FAIL:%03X\n", ret);
		return ret;
	}

	// 将ECC签名结构体转换为字节数组
	memcpy(signature, eccSignature.r, 32);
	memcpy(signature + 32, eccSignature.s, 32);
	*signLen = 64; // SM2签名固定为64字节(r和s各32字节)

	// 导出公钥
	ret = exportPublicKey(hKey, &publicKey);
	if (ret != FME_OK)
	{
		printf("exportPublicKey FAIL:%03X\n", ret);
		return ret;
	}


	// ret = FM_SIC_ECCVerify(hDev, FM_ALG_SM2_1, hKey, NULL, (FM_U8 *)data, dataLen, &eccSignature);
	ret = FM_SIC_ECCVerify(hDev, FM_ALG_SM2_1, FM_HKEY_FROM_HOST, &publicKey, (FM_U8 *)data, dataLen, &eccSignature);
	if (ret != FME_OK)
	{
		printf("ECCVerify FAIL:%03X\n", ret);
		return ret;
	}
	printf("ECCVerify OK\n");
	return FME_OK;
}
int RunTest()
{
	FM_S8 keySerial[36];
	int ret;

	printf("\n=== 开始执行自动测试 ===\n");

	// 1. 获取设备序列号
	printf("\n[步骤1] 获取设备序列号\n");
	ret = GetDev(keySerial);
	if (ret != FME_OK)
	{
		printf("获取设备序列号失败\n");
		return ret;
	}

	// 2. 打开设备
	printf("\n[步骤2] 打开设备\n");
	ret = OpenDev(keySerial);
	if (ret != FME_OK)
	{
		printf("测试失败：打开设备失败\n");
		return ret;
	}

	// 3. 操作员登录
	printf("\n[测试步骤 3] 操作员登录\n");
	ret = DevOperLogin();
	if (ret != FME_OK)
	{
		printf("测试失败：操作员登录失败\n");
		goto cleanup;
	}

	// 4. 生成随机数
	printf("\n[测试步骤 4] 生成随机数\n");
	FM_U8 random[32] = {0};
	ret = GenRandom(32, random);
	if (ret != FME_OK)
	{
		printf("测试失败：生成随机数失败\n");
		goto cleanup;
	}

	// 5. 生成ECC密钥对
	printf("\n[测试步骤 5] 生成ECC密钥对\n");
	ret = GenECCKeypair();
	if (ret != FME_OK)
	{
		printf("测试失败：生成ECC密钥对失败\n");
		goto cleanup;
	}
	// 6.签名验签测试
	printf("\n[测试步骤 6] 签名验签测试\n");
	unsigned char testData[] = "Test Data For Signature";
	unsigned char signature[64] = {0};
	FM_U32 signLen = sizeof(signature);
	printf("请输入要测试的密钥索引(0-31): ");
	int testKeyIndex;
	scanf("%d", &testKeyIndex);
	if (testKeyIndex < 0 || testKeyIndex > 31)
	{
		printf("\n错误：密钥索引必须在0-31之间\n");
		goto cleanup;
	}
	ret = signVerifyTest(random, sizeof(random), signature, &signLen, (FM_HKEY)(testKeyIndex & 0x1F));
	if (ret != FME_OK)
	{
		printf("测试失败：签名验签测试失败\n");
		goto cleanup;
	}
	// 7.删除密钥测试
	printf("\n[测试步骤 7] 删除密钥测试\n");
	ret = delEccKey((FM_HKEY)(testKeyIndex & 0x1F));
	if (ret != FME_OK)
	{
		printf("测试失败：删除密钥失败\n");
		goto cleanup;
	}

	// 8. 用户登出
	printf("\n[测试步骤 8] 用户登出\n");
	ret = DevUserLogout();
	if (ret != FME_OK)
	{
		printf("测试失败：用户登出失败\n");
		goto cleanup;
	}

	printf("\n=== 测试全部完成，结果：成功 ===\n");

cleanup:
	printf("\n[清理] 执行清理操作\n");
	DevUserLogout();
	return ret;
}
int AddUserKey()
{
	char username[256] = {0};
	const char *sudo_user = getenv("SUDO_USER");
	if (sudo_user != NULL && strlen(sudo_user) > 0)
	{
		strncpy(username, sudo_user, sizeof(username) - 1);
	}
	else
	{
		// 如果SUDO_USER为空，尝试使用SUDO_UID
		const char *sudo_uid_str = getenv("SUDO_UID");
		uid_t uid;
		if (sudo_uid_str != NULL)
		{
			uid = (uid_t)atoi(sudo_uid_str);
		}
		else
		{
			uid = getuid();
		}

		struct passwd *pw = getpwuid(uid);
		if (pw == NULL || pw->pw_name == NULL)
		{
			printf("\n获取用户名失败\n");
			return FME_FAIL;
		}
		strncpy(username, pw->pw_name, sizeof(username) - 1);
	}

	if (strlen(username) == 0)
	{
		printf("\n用户名为空\n");
		return FME_FAIL;
	}
	printf("\n当前用户: %s\n", username);

	// 初始化设备
	printf("\n[步骤1] 获取设备序列号\n");
	FM_S8 keySerial[36] = {0};
	FM_U32 u32Ret = GetDev(keySerial);
	if (u32Ret != FME_OK)
	{
		printf("获取设备序列号失败\n");
		return FME_FAIL;
	}

	printf("\n[步骤2] 打开设备\n");
	u32Ret = OpenDev((FM_U8 *)keySerial);
	if (u32Ret != FME_OK)
	{
		printf("打开设备失败\n");
		return FME_FAIL;
	}

	printf("\n[步骤3] 操作员登录\n");
	u32Ret = DevOperLogin();
	if (u32Ret != FME_OK)
	{
		printf("操作员登录失败\n");
		CloseDev();
		return FME_FAIL;
	}

	// 生成新密钥对
	printf("\n[步骤4] 生成密钥对\n");
	FM_ECC_PublicKey pPubkey;
	FM_ECC_PrivateKey pPrikey;

	printf("请输入密钥索引(0-31): ");
	int keyIndex;
	scanf("%d", &keyIndex);

	if (keyIndex < 0 || keyIndex > 31)
	{
		printf("\n错误：密钥索引必须在0-31之间\n");
		DevUserLogout();
		CloseDev();
		return FME_FAIL;
	}

	// 最高位设置为0表示永久存储，其他位为密钥索引
	FM_HKEY hkey = (FM_HKEY)(keyIndex & 0x1F);
	u32Ret = FM_SIC_GenECCKeypair(hDev, FM_ALG_SM2_1, &hkey, &pPubkey, &pPrikey);
	if (u32Ret != FME_OK)
	{
		printf("\n生成密钥对失败:%03X\n", u32Ret);
		DevUserLogout();
		CloseDev();
		return u32Ret;
	}
	// 签名验签测试
	printf("\n[步骤5] 签名验签测试\n");
	unsigned char testData[] = "Test Data For Signature";
	unsigned char signature[64] = {0};
	FM_U32 signLen = sizeof(signature);
	u32Ret = signVerifyTest(testData, sizeof(testData), signature, &signLen, hkey);
	if (u32Ret != FME_OK)
	{
		printf("签名验签测试失败\n");
		DevUserLogout();
		CloseDev();
		return u32Ret;
	}
	

	// 读取现有文件内容
	FILE *fp = fopen("/etc/pam.d/upk.key", "r");
	char tempFile[] = "/etc/pam.d/upk.key.tmp";
	FILE *fpTemp = fopen(tempFile, "w");
	if (fpTemp == NULL)
	{
		printf("无法创建临时文件\n");
		if (fp != NULL)
			fclose(fp);
		return FME_FAIL;
	}

	int found = 0;
	if (fp != NULL)
	{
		char line[1024];
		char existingUser[256];
		char existingSerial[36];
		char existingPubKey[512];
		int existingKeyIndex;

		while (fgets(line, sizeof(line), fp))
		{
			if (sscanf(line, "%[^:]:%[^:]:%d:%[^\n]", existingUser, existingSerial, &existingKeyIndex, existingPubKey) == 4)
			{
				if (strcmp(existingUser, username) == 0 && strcmp(existingSerial, keySerial) == 0)
				{
					// 找到匹配记录，写入新的密钥索引和公钥
					fprintf(fpTemp, "%s:%s:%d:04", username, keySerial, keyIndex);
					for (int i = 0; i < 32; i++)
					{
						fprintf(fpTemp, "%02X", pPubkey.x[i]);
					}
					for (int i = 0; i < 32; i++)
					{
						fprintf(fpTemp, "%02X", pPubkey.y[i]);
					}
					fprintf(fpTemp, "\n");
					found = 1;
				}
				else
				{
					// 复制其他记录
					fputs(line, fpTemp);
				}
			}
		}
		fclose(fp);
	}

	// 如果没有找到匹配记录，添加新记录
	if (!found)
	{
		fprintf(fpTemp, "%s:%s:%d:04", username, keySerial, keyIndex);
		for (int i = 0; i < 32; i++)
		{
			fprintf(fpTemp, "%02X", pPubkey.x[i]);
		}
		for (int i = 0; i < 32; i++)
		{
			fprintf(fpTemp, "%02X", pPubkey.y[i]);
		}
		fprintf(fpTemp, "\n");
	}

	fclose(fpTemp);

	// 替换原文件
	if (rename(tempFile, "/etc/pam.d/upk.key") != 0)
	{
		printf("更新文件失败\n");
		DevUserLogout();
		CloseDev();
		return FME_FAIL;
	}

	// 设置文件权限为 644 (rw-r--r--)
	chmod("/etc/pam.d/upk.key", 0644);

	printf("\n用户密钥信息已%s /etc/pam.d/upk.key\n", found ? "更新到" : "保存到");

	// 清理
	printf("\n[步骤5] 清理\n");

	return FME_OK;
}
int delEccKey(FM_HKEY hKey)
{
	return FM_SIC_DelECCKeypair(hDev, hKey);
}
int exportPublicKey(FM_HKEY hKey, FM_ECC_PublicKey *pPubkey)
{
	return FM_SIC_ExportECCKeypair(hDev, hKey, pPubkey, NULL);
}
int getDeviceInfo()
{
	FM_DEV_INFO dinfo;
	// 获取设备信息
	int ret = FM_SIC_GetDeviceInfo(hDev, &dinfo);
	if (ret != FME_OK)
	{
		printf("获取设备信息失败\n");
		return ret;
	}
	printf("设备制造商: %s\n", dinfo.au8IssuerName);
	printf("设备型号: %s\n", dinfo.au8DeviceName);
	printf("设备状态: %d\n", dinfo.u32State);

	// 解析对称算法掩码
	printf("设备支持的对称算法: \n");
	if (dinfo.au32SymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_SSF33))
		printf("  - SSF33\n");
	if (dinfo.au32SymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_SM1))
		printf("  - SM1\n");
	if (dinfo.au32SymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_SM4))
		printf("  - SM4\n");
	if (dinfo.au32SymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_DES))
		printf("  - DES\n");
	if (dinfo.au32SymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_3DES))
		printf("  - 3DES\n");
	if (dinfo.au32SymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_AES))
		printf("  - AES_128\n");
	if (dinfo.au32SymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_AES192))
		printf("  - AES_192\n");
	if (dinfo.au32SymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_AES256))
		printf("  - AES_256\n");

	// 解析非对称算法掩码
	printf("设备支持的非对称算法: \n");
	if (dinfo.au32AsymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_RSA1024))
		printf("  - RSA_1024\n");
	if (dinfo.au32AsymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_RSA2048))
		printf("  - RSA_2048\n");
	if (dinfo.au32AsymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_RSA4096))
		printf("  - RSA_4096\n");
	if (dinfo.au32AsymAlgMask[0] & FM_ALG_GETMASK(FM_ALG_SM2_1))
		printf("  - SM2\n");

	// 解析杂凑算法掩码
	printf("设备支持的杂凑算法: \n");
	if (dinfo.au32HashAlgMask[0] & FM_ALG_GETMASK(FM_ALG_SM3))
		printf("  - SM3\n");
	if (dinfo.au32HashAlgMask[0] & FM_ALG_GETMASK(FM_ALG_SHA1))
		printf("  - SHA1\n");
	if (dinfo.au32HashAlgMask[0] & FM_ALG_GETMASK(FM_ALG_SHA256))
		printf("  - SHA256\n");
	if (dinfo.au32HashAlgMask[0] & FM_ALG_GETMASK(FM_ALG_SHA384))
		printf("  - SHA384\n");
	if (dinfo.au32HashAlgMask[0] & FM_ALG_GETMASK(FM_ALG_SHA512))
		printf("  - SHA512\n");
	if (dinfo.au32HashAlgMask[0] & FM_ALG_GETMASK(FM_ALG_MD5))
		printf("  - MD5\n");

	// 解析密钥数目
	printf("\n密钥容量信息:\n");
	printf("对称密钥:\n");
	printf("  - 永久密钥数目: %d\n", dinfo.au32SymKeyNum[0] & 0xFFFF);
	printf("  - 临时密钥数目: %d\n", (dinfo.au32SymKeyNum[0] >> 16) & 0xFFFF);

	printf("非对称密钥:\n");
	printf("  - 永久密钥数目: %d\n", dinfo.au32AsymKeyNum[0] & 0xFFFF);
	printf("  - 临时密钥数目: %d\n", (dinfo.au32AsymKeyNum[0] >> 16) & 0xFFFF);

	printf("\n存储信息:\n");
	printf("文件存储空间: %d 字节\n", dinfo.u32FileSize);
	printf("支持目录数目: %d\n", dinfo.u16DirNum);
	printf("支持文件数目: %d\n", dinfo.u16FileNum);
	return FME_OK;
}
