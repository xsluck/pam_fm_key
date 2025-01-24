# PAM FM Key 认证模块

这是一个基于PAM(Pluggable Authentication Modules)的密码设备认证模块，支持使用渔翁密码设备进行系统认证。

## 功能特性

- 支持渔翁密码设备的系统认证）
- 提供完整的设备管理和测试工具

## 系统要求

- Linux系统
- GCC 编译器
- PAM开发库
- 渔翁密码设备驱动

## 构建说明

### 1. 安装依赖

```bash
# Debian/Ubuntu系统
sudo apt-get install build-essential
sudo apt-get install libpam0g-dev

# RHEL/CentOS系统
sudo yum groupinstall "Development Tools"
sudo yum install pam-devel
```

### 2. 编译

```bash
# 编译整个项目（包含 pam_fm_key.so、fm_key_test 和 pam_test）
make

# 清理编译
make clean
```

### 3. 安装

```bash
# 安装PAM模块
sudo make install

# 或手动安装 拷贝so到安全目录下
sudo cp pam_fm_key.so /lib/security/
```

## 配置说明

### 1. PAM配置

在`/etc/pam.d/`目录下添加或修改相应的服务配置文件，例如：

```
# /etc/pam.d/sudo
auth    sufficient      pam_fm_key.so
auth    include        system-auth
```
配置使用sudo命令时使用key进行认证

### 2. 密钥配置

密钥信息存储在`/etc/pam.d/upk.key`文件中，格式为：
```
username:device_serial:key_index:public_key
```
需要使用`fm_key_test`工具选择添加用户密钥选项生成（需要使用管理员权限）。

## 测试工具使用

项目提供了完整的测试程序`fm_key_test`，可以进行以下操作：

1. 设备检测和信息查询
2. 密钥对生成和管理
3. 签名验签测试
4. 设备登录测试

使用方法：
```bash
# 运行测试程序根据提示即可
sudo ./fm_key_test

=== FM Key Test Program ===

一级菜单:
1. 获取设备序列号
2. 打开设备
3. 关闭设备
0. 退出程序
请输入选项 (0-3): 
```



## 故障排除

1. 设备无法识别
   - 检查设备是否正确插入
   - 确认驱动是否正确安装
   - 检查用户权限

2. 认证失败
   - 确认密钥配置文件权限
   - 验证公钥信息是否正确
   - 检查PAM配置是否正确



### PAM认证测试工具

项目提供了专门的PAM认证测试工具`pam_test`，用于测试PAM模块的认证功能。

#### 配置说明

1. 创建PAM服务配置文件：
```bash
# 创建测试服务配置文件
sudo touch /etc/pam.d/ukey-auth

# 设置适当的权限
sudo chmod 644 /etc/pam.d/ukey-auth
```

2. 编辑配置文件内容：
```bash
sudo vi /etc/pam.d/ukey-auth
```

添加以下内容：
```
# /etc/pam.d/ukey-auth
auth    required    pam_fm_key.so
account required    pam_permit.so
password required   pam_permit.so
session  required   pam_permit.so
```

说明：
- `auth required pam_fm_key.so`: 指定使用 fm_key 模块进行认证
- 其他行是为了满足 PAM 配置的完整性要求
- `required` 表示认证必须通过才能继续


#### 使用方法
```bash
# 基本用法
./pam_test [用户名]

# 示例
sudo ./pam_test root     # 测试root用户的认证
./pam_test $(whoami)    # 测试当前用户的认证

Open Device OK!

Close Device OK
认证成功!

./pam_test $(whoami) #认证失败

认证失败: Authentication failure
```


#### 测试结果说明
- 成功：显示"认证成功!"
- 失败：显示"认证失败: Authentication failure"

测试成功，代表模块正常工作，即可删除  /etc/pam.d/ukey-auth

#### 调试提示
- 认证失败时查看系统日志获取更多信息

## 开发说明

### 主要文件说明

- `pam_fm_key.c`: PAM模块主程序
- `fm_key_test.c`: 测试程序
- `pam_test.c`: PAM认证测试工具
- `fm_def.h`: 基础定义头文件
- `Makefile`: 构建配置文件

### 本文由AI生成，如有错误请见谅。

## 免责声明

### 知识产权声明
本项目是一个开源的PAM认证模块实现。项目中使用的所有第三方组件均遵循其原有的开源许可证。如果本项目中的代码或文档侵犯了您的知识产权，请及时与我联系，我会立即进行处理。

### 使用限制
1. 本项目仅供学习和研究使用，不得用于商业用途
2. 禁止将本项目用于任何非法用途
3. 使用本项目所造成的任何直接或间接损失，项目维护者不承担任何责任

### 安全提示
本项目涉及系统认证安全，在生产环境中使用前请务必：
1. 进行充分的安全测试
2. 遵守相关的安全规范和法律法规
3. 确保使用环境的安全性

如有任何安全问题或建议，请及时报告给项目维护者。
