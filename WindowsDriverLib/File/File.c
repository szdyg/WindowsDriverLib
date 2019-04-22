#include "File.h"

#define FILE_TAG   'elif'


NTSTATUS CreateDirLink(IN PUNICODE_STRING ucSrcPath,IN PUNICODE_STRING ucTargetPath)
{
    NTSTATUS   status = STATUS_SUCCESS;
    HANDLE     hFile = NULL;
    ULONG      uBufSize = 0x1000;
    IO_STATUS_BLOCK      IoStausBlock = { 0 };
    OBJECT_ATTRIBUTES    oa = { 0 };
    PREPARSE_DATA_BUFFER pReparseBuf = NULL;

    do
    {
        InitializeObjectAttributes(&oa, &ucSrcPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenFile(&hFile, GENERIC_READ | GENERIC_WRITE, &oa, &IoStausBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("ZwOpenFile Failed: 0x%x\n", (ULONG32)status));
            break;
        }
        uBufSize = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) + ucTargetPath->Length + 16 * sizeof(WCHAR);
        pReparseBuf = ExAllocatePoolWithTag(NonPagedPool, uBufSize, FILE_TAG);
        if (pReparseBuf == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            KdPrint(("ExAllocatePoolWithTag Failed\n"));
            break;
        }

        RtlZeroMemory(pReparseBuf, uBufSize);
        pReparseBuf->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
        pReparseBuf->Reserved = 0;
        pReparseBuf->MountPointReparseBuffer.SubstituteNameOffset = 0;
        pReparseBuf->MountPointReparseBuffer.SubstituteNameLength = ucTargetPath->Length + sizeof(L'\0');
        pReparseBuf->MountPointReparseBuffer.PrintNameOffset = ucTargetPath->Length + sizeof(L'\0') + sizeof(L'\0');
        pReparseBuf->MountPointReparseBuffer.PrintNameLength = 0;
        RtlCopyMemory(pReparseBuf->MountPointReparseBuffer.PathBuffer, ucTargetPath->Buffer, ucTargetPath->Length);
        pReparseBuf->MountPointReparseBuffer.PathBuffer[(USHORT)(ucTargetPath->Length / 2)] = L'\\';
        pReparseBuf->ReparseDataLength = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) + pReparseBuf->MountPointReparseBuffer.PrintNameOffset + pReparseBuf->MountPointReparseBuffer.PrintNameLength + sizeof(L'\0') - REPARSE_DATA_BUFFER_HEADER_SIZE;

        status = ZwFsControlFile(
            hFile,
            NULL,
            NULL,
            NULL, 
            &IoStausBlock,
            FSCTL_SET_REPARSE_POINT,
            pReparseBuf, 
            pReparseBuf->ReparseDataLength + REPARSE_DATA_BUFFER_HEADER_SIZE,
            NULL, 
            0);

        if (!NT_SUCCESS(status))
        {
            KdPrint(("ZwFsControlFile Failed: 0x%x\n", (ULONG32)status));
            break;
        }

    } while (FALSE);

    if (hFile != NULL)
    {
        ZwClose(hFile);
        hFile = NULL;
    }

    if (pReparseBuf != NULL)
    {
        ExFreePoolWithTag(pReparseBuf, FILE_TAG);
        pReparseBuf = NULL;
    }
    return status;
}

BOOLEAN IsDirExist(IN PUNICODE_STRING path)
{
    NTSTATUS status = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK     IoStatus;
    HANDLE              FileHandle = NULL;

    InitializeObjectAttributes(&oa, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwCreateFile(&FileHandle,
        GENERIC_READ,
        &oa,
        &IoStatus,
        0,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_WRITE | FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
        NULL,
        0);
    return NT_SUCCESS(status);
}


NTSTATUS CopyFile(IN PUNICODE_STRING ucReadpath, IN PUNICODE_STRING ucWritepath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hRead = NULL;
    HANDLE hWrite = NULL;
    PUCHAR pBuffer = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK IoStatusRead = { 0 };
    IO_STATUS_BLOCK IoStatusWrite = { 0 };
    LARGE_INTEGER Offset = { 0 };
    ULONG uReadlen;
    ULONG uCopySize = 4 * 1024 * 1024;      //4MB

    do
    {

        if (NULL == ucReadpath || NULL == ucWritepath)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        InitializeObjectAttributes(&oa, ucReadpath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwCreateFile(
            &hRead,
            FILE_GENERIC_READ,
            &oa,
            &IoStatusRead,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        InitializeObjectAttributes(&oa, ucWritepath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwCreateFile(
            &hWrite,
            FILE_GENERIC_WRITE,
            &oa,
            &IoStatusWrite,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        pBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, uCopySize, FILE_TAG);
        if (NULL == pBuffer)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        while (TRUE)
        {
            status = ZwReadFile(
                hRead,
                NULL,
                NULL,
                NULL,
                &IoStatusRead,
                pBuffer,
                uCopySize,
                &Offset,
                NULL);

            if (!NT_SUCCESS(status))
            {
                if (STATUS_END_OF_FILE == status)
                {
                    status = STATUS_SUCCESS;
                }
                break;
            }

            uReadlen = (ULONG)IoStatusRead.Information;

            status = ZwWriteFile(
                hWrite,
                NULL,
                NULL,
                NULL,
                &IoStatusWrite,
                pBuffer,
                uReadlen,
                &Offset,
                NULL);
            if (!NT_SUCCESS(status))
            {
                break;
            }
            Offset.QuadPart += uReadlen;
        }

    } while (FALSE);

    if (hRead != NULL)
    {
        ZwClose(hRead);
        hRead = NULL;
    }

    if (hWrite != NULL)
    {
        ZwClose(hWrite);
        hWrite = NULL;
    }

    if (pBuffer != NULL)
    {
        ExFreePoolWithTag(pBuffer,FILE_TAG);
        pBuffer = NULL;
    }

    return status;
}


NTSTATUS DeleteFile(IN PUNICODE_STRING ucFilepath)
{
    HANDLE  hFile = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    FILE_DISPOSITION_INFORMATION FileInfo = { 0 };

    if (IsFileExist(ucFilepath))
    {
        do
        {
            InitializeObjectAttributes(&oa, &ucFilepath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
            status = ZwOpenFile(
                &hFile, 
                GENERIC_ALL,
                &oa,
                &IoStatusBlock,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

            if (!NT_SUCCESS(status))
            {
                break;
            }

            FileInfo.DeleteFile = TRUE;
            status = ZwSetInformationFile(hFile, &IoStatusBlock, &FileInfo, sizeof(FileInfo), FileDispositionInformation);
            if (!NT_SUCCESS(status))
            {
                break;
            }

        } while (FALSE);

        if (hFile != NULL)
        {
            ZwClose(hFile);
            hFile = NULL;
        }
    }
    return status;
}


NTSTATUS CreateDirLinkForce(IN PUNICODE_STRING ucSrcPath, IN PUNICODE_STRING ucTargetPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    if (IsDirExist(ucSrcPath))
    {
        status = DeleteDir(ucTargetPath);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    return CreateDirLink(ucSrcPath, ucTargetPath);
}

NTSTATUS CreateDir(IN PUNICODE_STRING ucTargetPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PWCHAR pEndPtr = ucTargetPath->Buffer + ucTargetPath->Length / sizeof(WCHAR) - 1;
    PWCHAR pCurSubDir = NULL;
    PWCHAR pNextSubDir = NULL;
    PWCHAR pStartPath = ucTargetPath->Buffer;
    HANDLE hRootDir = NULL;
    HANDLE hNewDir = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING    subKeyStr = { 0 };
    IO_STATUS_BLOCK   ioStatusBlock = { 0 };
    UNICODE_STRING    prefixStr = RTL_CONSTANT_STRING(L"\\??\\");

    do
    {
        if (ucTargetPath->Length == 0)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }
        if (RtlPrefixUnicodeString(&prefixStr, ucTargetPath, TRUE))
        {
            USHORT strLen = sizeof(L"\\??\\X:\\") - sizeof(L'\0');
            if (ucTargetPath->Length >= strLen)
            {
                if (ucTargetPath->Buffer[5] == L':' && ucTargetPath->Buffer[6] == L'\\')
                {
                    subKeyStr.Length = strLen;
                    subKeyStr.MaximumLength = subKeyStr.Length;
                    subKeyStr.Buffer = ucTargetPath->Buffer;
                    InitializeObjectAttributes(&oa, &subKeyStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

                    status = ZwCreateFile(
                        &hRootDir,
                        GENERIC_READ | GENERIC_WRITE,
                        &oa,
                        &ioStatusBlock,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_OPEN_IF,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        NULL,
                        0);
                    if (!NT_SUCCESS(status))
                    {
                        KdPrint(("ZwCreateFile %wZ failed 0x%X\n", &subKeyStr, (ULONG32)status));
                        break;
                    }

                    if (ucTargetPath->Length == strLen)
                    {
                        break;
                    }

                    pStartPath = ucTargetPath->Buffer + strLen / sizeof(WCHAR);
                }
            }
        }

        for (pCurSubDir = pStartPath, pNextSubDir = pStartPath;; pNextSubDir++)
        {
            BOOLEAN isEnd = pNextSubDir == pEndPtr;

            if (*pNextSubDir == L'\\' || pNextSubDir == pEndPtr)
            {
                USHORT strLen = (pNextSubDir - pCurSubDir) * sizeof(WCHAR);
                subKeyStr.Length = strLen;
                subKeyStr.MaximumLength = strLen;
                subKeyStr.Buffer = pCurSubDir;

                if (pNextSubDir == pEndPtr)
                {
                    subKeyStr.Length += sizeof(WCHAR);
                    subKeyStr.MaximumLength = subKeyStr.Length;
                }

                if (subKeyStr.Length == 0)
                {
                    if (isEnd)
                    {
                        status = STATUS_SUCCESS;
                        break;
                    }
                    else
                    {
                        pCurSubDir = pNextSubDir + 1;
                        continue;
                    }
                }
                InitializeObjectAttributes(&oa, &subKeyStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, hRootDir, NULL);

                status = ZwCreateFile(
                    &hNewDir,
                    GENERIC_READ | GENERIC_WRITE,
                    &oa,
                    &ioStatusBlock,
                    NULL,
                    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_OPEN_IF,
                    FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                    NULL,
                    0);
                if (!NT_SUCCESS(status))
                {
                    KdPrint(("ZwCreateFile %wZ failed 0x%X\n", &subKeyStr, (ULONG32)status));
                    break;
                }

                if (hRootDir != NULL)
                {
                    ZwClose(hRootDir);
                    hRootDir = NULL;
                }

                hRootDir = hNewDir;

                pCurSubDir = pNextSubDir + 1;
            }

            if (isEnd)
            {
                break;
            }
        }
    } while (FALSE);

    if (hRootDir != NULL && hRootDir != hNewDir)
    {
        ZwClose(hRootDir);
    }

    if (hNewDir != NULL)
    {
        ZwClose(hNewDir);
    }

    return status;
}

NTSTATUS DeleteDir(IN PUNICODE_STRING ucTargetPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    HANDLE hFile = NULL;
    HANDLE hDir = NULL;
    ULONG fileDirInfoSize = 4 * 1024;   //4KB
    ULONG removeDirStackIdx = 0;
    PFILE_DIRECTORY_INFORMATION pDirInfo = NULL;
    PFILE_DIRECTORY_INFORMATION pDirInfoNew = NULL;
    BOOLEAN bIsRescan = TRUE;

    do
    {
        pDirInfo = ExAllocatePoolWithTag(NonPagedPool, fileDirInfoSize, FILE_TAG);
        if (pDirInfo == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        InitializeObjectAttributes(&oa, &ucTargetPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenFile(
            &hDir,
            GENERIC_ALL | FILE_LIST_DIRECTORY,
            &oa,
            &IoStatusBlock,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        while (TRUE)
        {
            UNICODE_STRING ucFilePath = { 0 };
            status = ZwQueryDirectoryFile(hDir, NULL, NULL, NULL, &IoStatusBlock, pDirInfo, fileDirInfoSize, FileDirectoryInformation, TRUE, NULL, bIsRescan);
            if (!NT_SUCCESS(status))
            {
                if (status == STATUS_BUFFER_OVERFLOW)
                {
                    fileDirInfoSize = fileDirInfoSize * 2;
                    pDirInfoNew = ExAllocatePoolWithTag(NonPagedPool, fileDirInfoSize, FILE_TAG);
                    if (pDirInfoNew == NULL)
                    {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                        break;
                    }
                    ExFreePoolWithTag(pDirInfo, FILE_TAG);
                    pDirInfo = pDirInfoNew;
                    continue;
                }
                else if (status == STATUS_NO_MORE_FILES)
                {
                    status = STATUS_SUCCESS;
                }
                break;
            }
            bIsRescan = FALSE;
            ucFilePath.Buffer = pDirInfo->FileName;
            ucFilePath.Length = (USHORT)pDirInfo->FileNameLength;
            ucFilePath.MaximumLength = ucFilePath.Length;
            if (pDirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                status = DeleteDir(&ucFilePath);
            }
            else
            {
                status = DeleteFile(&ucFilePath);
            }
            if (!NT_SUCCESS(status))
            {
                break;
            }
        }
    } while (FALSE);

    if (pDirInfo != NULL)
    {
        ExFreePoolWithTag(pDirInfo, FILE_TAG);
    }
    if (hDir != NULL)
    {
        ZwClose(hDir);
    }
    if (hFile != NULL)
    {
        ZwClose(hFile);
    }
    return status;
}


NTSTATUS CreateFileLink(IN PUNICODE_STRING ucSrcPath, IN PUNICODE_STRING ucTarPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    HANDLE hFIle = NULL;
    PREPARSE_DATA_BUFFER pReparseBuf = NULL;
    PUCHAR pData = NULL;
    ULONG uBufSize = 0x1000;
    do
    {
        InitializeObjectAttributes(&oa, ucSrcPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenFile(&hFIle, GENERIC_READ | GENERIC_WRITE, &oa, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        uBufSize = FIELD_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) + ucTarPath->Length * 2 + 32 * sizeof(WCHAR);
        pReparseBuf = ExAllocatePoolWithTag(NonPagedPool, uBufSize, FILE_TAG);
        if (pReparseBuf == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlZeroMemory(pReparseBuf, uBufSize);
        pReparseBuf->ReparseTag = IO_REPARSE_TAG_SYMLINK;
        pReparseBuf->Reserved = 0;
        pReparseBuf->SymbolicLinkReparseBuffer.Flags = 0x0;


        pReparseBuf->SymbolicLinkReparseBuffer.PrintNameOffset = 0;
        pReparseBuf->SymbolicLinkReparseBuffer.PrintNameLength = ucTarPath->Length - sizeof(WCHAR) * 4;
        pReparseBuf->SymbolicLinkReparseBuffer.SubstituteNameOffset = ucTarPath->Length - sizeof(WCHAR) * 4;
        pReparseBuf->SymbolicLinkReparseBuffer.SubstituteNameLength = ucTarPath->Length;
        RtlCopyMemory(pReparseBuf->SymbolicLinkReparseBuffer.PathBuffer, &ucTarPath->Buffer[4], ucTarPath->Length - sizeof(WCHAR) * 4);


        pData = &(UCHAR)(pReparseBuf->SymbolicLinkReparseBuffer.PathBuffer[0]);
        pData += ucTarPath->Length - sizeof(WCHAR) * 4;
        RtlCopyMemory(pData, ucTarPath->Buffer, ucTarPath->Length);


        pReparseBuf->ReparseDataLength = FIELD_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) - REPARSE_DATA_BUFFER_HEADER_SIZE + ucTarPath->Length * 2 - sizeof(WCHAR) * 4;

        status = ZwFsControlFile(hFIle, NULL, NULL, NULL, &IoStatusBlock, FSCTL_SET_REPARSE_POINT, pReparseBuf, pReparseBuf->ReparseDataLength + REPARSE_DATA_BUFFER_HEADER_SIZE, NULL, 0);
        if (!NT_SUCCESS(status))
        {
            break;
        }

    } while (FALSE);

    if (hFIle != NULL)
    {
        ZwClose(hFIle);
        hFIle = NULL;
    }

    if (pReparseBuf != NULL)
    {
        ExFreePoolWithTag(pReparseBuf, FILE_TAG);
        pReparseBuf = NULL;
    }
    return status;
}

NTSTATUS CreateFileLinkForce(IN PUNICODE_STRING ucSrcPath, IN PUNICODE_STRING ucTargetPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    HANDLE fileHnd = NULL;
    if (NT_SUCCESS(DeleteFile(ucSrcPath)))
    {
        InitializeObjectAttributes(&oa, ucSrcPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwCreateFile(
            &fileHnd,
            GENERIC_READ | GENERIC_WRITE,
            &oa,
            &IoStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SUPERSEDE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("ZwCreateFile Failed: 0x%x\n", (ULONG32)status));
            return status;
        }
        else
        {
            ZwClose(fileHnd);
        }
    }

    status = CreateFileLink(ucSrcPath, ucTargetPath);
    return status;
}


BOOLEAN IsFileExist(IN PUNICODE_STRING ucFilepath)
{
    NTSTATUS status = STATUS_SUCCESS;
    FILE_NETWORK_OPEN_INFORMATION fileInfo = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };
    InitializeObjectAttributes(&oa, ucFilepath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwQueryFullAttributesFile(&oa, &fileInfo);
    return NT_SUCCESS(status);
}
