#pragma once
#include <ntddk.h>
#include <ntifs.h>


//************************************
// 函数名:   IsDirExist
// 权限：    public 
// 返回值:   BOOLEAN
// 参数：    IN PUNICODE_STRING path          目录路径
// 说明：    检测目录是否存在
//************************************
BOOLEAN IsDirExist(IN PUNICODE_STRING ucDirPath);

//************************************
// 函数名:   IsFileExist
// 权限：    public 
// 返回值:   BOOLEAN
// 参数：    IN PUNICODE_STRING path          文件路径
// 说明：    检测文件是否存在
//************************************
BOOLEAN IsFileExist(IN PUNICODE_STRING ucFilepath);


//************************************
// 函数名:   CopyFile
// 权限：    public 
// 返回值:   NTSTATUS
// 参数：    IN PUNICODE_STRING ucReadpath         读取的文件路径
// 参数：    IN PUNICODE_STRING ucWritepath        写入的文件路径
// 说明：    拷贝文件
//************************************
NTSTATUS CopyFile(IN PUNICODE_STRING ucReadpath, IN PUNICODE_STRING ucWritepath);


//************************************
// 函数名:   CreateFileLink
// 权限：    public 
// 返回值:   NTSTATUS
// 参数：    IN PUNICODE_STRING ucSrcpath        符号链接路径
// 参数：    IN PUNICODE_STRING ucTarpath        符号链接指向的路径（真实文件的路径）
// 说明：    创建文件软连接
//************************************
NTSTATUS CreateFileLink(IN PUNICODE_STRING ucSrcpath,IN PUNICODE_STRING ucTarpath);



//************************************
// 函数名:   CreateFileLinkForce
// 权限：    public 
// 返回值:   NTSTATUS
// 参数：    IN PUNICODE_STRING srcPath            符号链接路径
// 参数：    IN PUNICODE_STRING targetPath         符号链接指向的路径
// 说明：    强制创建文件符号链接
//************************************
NTSTATUS CreateFileLinkForce(IN PUNICODE_STRING ucSrcPath,IN PUNICODE_STRING ucTargetPath);



//************************************
// 函数名:   CreateDirLink
// 权限：    public 
// 返回值:   NTSTATUS
// 参数：    IN PUNICODE_STRING srcPath           符号链接路径
// 参数：    IN PUNICODE_STRING targetPath        符号链接指向的路径
// 说明：    创建目录软链接
//************************************
NTSTATUS CreateDirLink(IN PUNICODE_STRING ucSrcPath,IN PUNICODE_STRING ucTargetPath);


//************************************
// 函数名:   CreateDirLinkForce
// 权限：    public 
// 返回值:   NTSTATUS
// 参数：    IN PUNICODE_STRING srcPath           符号链接路径
// 参数：    IN PUNICODE_STRING targetPath        符号链接指向的路径
// 说明：    强制创建目录符号链接
//************************************
NTSTATUS CreateDirLinkForce(IN PUNICODE_STRING ucSrcPath, IN PUNICODE_STRING ucTargetPath);


//************************************
// 函数名:   CreateDir
// 权限：    public 
// 返回值:   NTSTATUS
// 参数：    IN PUNICODE_STRING targetPath       目标路径      以L"//??//"开头
// 说明：    一层一层创建目录
//************************************
NTSTATUS CreateDir(IN PUNICODE_STRING ucTargetPath);


//************************************
// 函数名:   DeleteDir
// 权限：    public 
// 返回值:   NTSTATUS
// 参数：    IN PUNICODE_STRING targetPath
// 说明：    删除目录
//************************************
NTSTATUS DeleteDir(IN PUNICODE_STRING ucTargetPath);



//************************************
// 函数名:   DeleteFile
// 权限：    public 
// 返回值:   NTSTATUS
// 参数：    IN PUNICODE_STRING ucFilepath
// 说明：    删除文件
//************************************
NTSTATUS DeleteFile(IN PUNICODE_STRING ucFilepath);