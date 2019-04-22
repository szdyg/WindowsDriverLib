#pragma once
#include <ntddk.h>
#include <ntifs.h>


//************************************
// ������:   IsDirExist
// Ȩ�ޣ�    public 
// ����ֵ:   BOOLEAN
// ������    IN PUNICODE_STRING path          Ŀ¼·��
// ˵����    ���Ŀ¼�Ƿ����
//************************************
BOOLEAN IsDirExist(IN PUNICODE_STRING ucDirPath);

//************************************
// ������:   IsFileExist
// Ȩ�ޣ�    public 
// ����ֵ:   BOOLEAN
// ������    IN PUNICODE_STRING path          �ļ�·��
// ˵����    ����ļ��Ƿ����
//************************************
BOOLEAN IsFileExist(IN PUNICODE_STRING ucFilepath);


//************************************
// ������:   CopyFile
// Ȩ�ޣ�    public 
// ����ֵ:   NTSTATUS
// ������    IN PUNICODE_STRING ucReadpath         ��ȡ���ļ�·��
// ������    IN PUNICODE_STRING ucWritepath        д����ļ�·��
// ˵����    �����ļ�
//************************************
NTSTATUS CopyFile(IN PUNICODE_STRING ucReadpath, IN PUNICODE_STRING ucWritepath);


//************************************
// ������:   CreateFileLink
// Ȩ�ޣ�    public 
// ����ֵ:   NTSTATUS
// ������    IN PUNICODE_STRING ucSrcpath        ��������·��
// ������    IN PUNICODE_STRING ucTarpath        ��������ָ���·������ʵ�ļ���·����
// ˵����    �����ļ�������
//************************************
NTSTATUS CreateFileLink(IN PUNICODE_STRING ucSrcpath,IN PUNICODE_STRING ucTarpath);



//************************************
// ������:   CreateFileLinkForce
// Ȩ�ޣ�    public 
// ����ֵ:   NTSTATUS
// ������    IN PUNICODE_STRING srcPath            ��������·��
// ������    IN PUNICODE_STRING targetPath         ��������ָ���·��
// ˵����    ǿ�ƴ����ļ���������
//************************************
NTSTATUS CreateFileLinkForce(IN PUNICODE_STRING ucSrcPath,IN PUNICODE_STRING ucTargetPath);



//************************************
// ������:   CreateDirLink
// Ȩ�ޣ�    public 
// ����ֵ:   NTSTATUS
// ������    IN PUNICODE_STRING srcPath           ��������·��
// ������    IN PUNICODE_STRING targetPath        ��������ָ���·��
// ˵����    ����Ŀ¼������
//************************************
NTSTATUS CreateDirLink(IN PUNICODE_STRING ucSrcPath,IN PUNICODE_STRING ucTargetPath);


//************************************
// ������:   CreateDirLinkForce
// Ȩ�ޣ�    public 
// ����ֵ:   NTSTATUS
// ������    IN PUNICODE_STRING srcPath           ��������·��
// ������    IN PUNICODE_STRING targetPath        ��������ָ���·��
// ˵����    ǿ�ƴ���Ŀ¼��������
//************************************
NTSTATUS CreateDirLinkForce(IN PUNICODE_STRING ucSrcPath, IN PUNICODE_STRING ucTargetPath);


//************************************
// ������:   CreateDir
// Ȩ�ޣ�    public 
// ����ֵ:   NTSTATUS
// ������    IN PUNICODE_STRING targetPath       Ŀ��·��      ��L"//??//"��ͷ
// ˵����    һ��һ�㴴��Ŀ¼
//************************************
NTSTATUS CreateDir(IN PUNICODE_STRING ucTargetPath);


//************************************
// ������:   DeleteDir
// Ȩ�ޣ�    public 
// ����ֵ:   NTSTATUS
// ������    IN PUNICODE_STRING targetPath
// ˵����    ɾ��Ŀ¼
//************************************
NTSTATUS DeleteDir(IN PUNICODE_STRING ucTargetPath);



//************************************
// ������:   DeleteFile
// Ȩ�ޣ�    public 
// ����ֵ:   NTSTATUS
// ������    IN PUNICODE_STRING ucFilepath
// ˵����    ɾ���ļ�
//************************************
NTSTATUS DeleteFile(IN PUNICODE_STRING ucFilepath);