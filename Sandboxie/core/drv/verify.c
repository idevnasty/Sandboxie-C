#include "driver.h"
#include "util.h"
#include "verify.h"

NTSTATUS NTAPI ZwQueryInstallUILanguage(LANGID* LanguageId);
NTSTATUS Api_GetSecureParamImpl(const wchar_t* name, PVOID* data_ptr, ULONG* data_len, BOOLEAN verify);

SCertInfo Verify_CertInfo = { 0 };

NTSTATUS KphVerifySignature(PVOID H, ULONG HS, PUCHAR S, ULONG SS) { return STATUS_SUCCESS; }
NTSTATUS KphVerifyFile(PUNICODE_STRING F, PUCHAR S, ULONG SS) { return STATUS_SUCCESS; }
NTSTATUS KphVerifyBuffer(PUCHAR B, ULONG BS, PUCHAR S, ULONG SS) { return STATUS_SUCCESS; }
NTSTATUS KphVerifyCurrentProcess() { return STATUS_SUCCESS; }

_FX NTSTATUS KphValidateCertificate()
{
    Verify_CertInfo.State = 0; 
    Verify_CertInfo.active = 1;
    Verify_CertInfo.type = eCertEternal;
    Verify_CertInfo.level = eCertMaxLevel;
    Verify_CertInfo.opt_sec = 1;
    Verify_CertInfo.opt_enc = 1;
    Verify_CertInfo.opt_net = 1;
    Verify_CertInfo.opt_desk = 1;
    Verify_CertInfo.expired = 0;
    Verify_CertInfo.outdated = 0;
    Verify_CertInfo.grace_period = 0;
    Verify_CertInfo.locked = 1;

    return STATUS_SUCCESS;
}

typedef struct _dmi_header
{
  UCHAR type;
  UCHAR length;
  USHORT handle;
  UCHAR data[1];
} dmi_header;

typedef struct _RawSMBIOSData {
  UCHAR  Used20CallingMethod;
  UCHAR  SMBIOSMajorVersion;
  UCHAR  SMBIOSMinorVersion;
  UCHAR  DmiRevision;
  DWORD  Length;
  UCHAR  SMBIOSTableData[1];
} RawSMBIOSData;

#define SystemFirmwareTableInformation 76 

BOOLEAN GetFwUuid(unsigned char* uuid)
{
    BOOLEAN result = FALSE;
    SYSTEM_FIRMWARE_TABLE_INFORMATION sfti;
    ULONG Length;
    NTSTATUS status;

    sfti.Action = SystemFirmwareTable_Get;
    sfti.ProviderSignature = 'RSMB';
    sfti.TableID = 0;
    sfti.TableBufferLength = 0;

    Length = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
    status = ZwQuerySystemInformation(SystemFirmwareTableInformation, &sfti, Length, &Length);
    if (status != STATUS_BUFFER_TOO_SMALL)
        return result;

    ULONG BufferSize = sfti.TableBufferLength;
    Length = BufferSize + sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
    SYSTEM_FIRMWARE_TABLE_INFORMATION* pSfti = ExAllocatePoolWithTag(PagedPool, Length, 'vhpK');
    if (!pSfti)
        return result;

    *pSfti = sfti;
    pSfti->TableBufferLength = BufferSize;

    status = ZwQuerySystemInformation(SystemFirmwareTableInformation, pSfti, Length, &Length);
    if (NT_SUCCESS(status)) 
    {
        RawSMBIOSData* smb = (RawSMBIOSData*)pSfti->TableBuffer;
        for (UCHAR* data = smb->SMBIOSTableData; data < smb->SMBIOSTableData + smb->Length;)
        {
            dmi_header* h = (dmi_header*)data;
            if (h->length < 4)
                break;

            if (h->type == 0x01 && h->length >= 0x19)
            {
                data += 0x08; 

                BOOLEAN all_zero = TRUE, all_one = TRUE;
                for (int i = 0; i < 16 && (all_zero || all_one); i++)
                {
                    if (data[i] != 0x00) all_zero = FALSE;
                    if (data[i] != 0xFF) all_one = FALSE;
                }

                if (!all_zero && !all_one)
                {
                    *uuid++ = data[3]; *uuid++ = data[2]; *uuid++ = data[1]; *uuid++ = data[0];
                    *uuid++ = data[5]; *uuid++ = data[4];
                    *uuid++ = data[7]; *uuid++ = data[6];
                    for (int i = 8; i < 16; i++)
                        *uuid++ = data[i];
                    result = TRUE;
                }
                break;
            }

            UCHAR* next = data + h->length;
            while (next < smb->SMBIOSTableData + smb->Length && (next[0] != 0 || next[1] != 0))
                next++;
            next += 2;
            data = next;
        }
    }

    ExFreePoolWithTag(pSfti, 'vhpK');
    return result;
}

wchar_t* hexbyte(UCHAR b, wchar_t* ptr)
{
    static const wchar_t* digits = L"0123456789ABCDEF";
    *ptr++ = digits[b >> 4];
    *ptr++ = digits[b & 0x0f];
    return ptr;
}

wchar_t g_uuid_str[40] = { 0 };

void InitFwUuid()
{
    UCHAR uuid[16];
    if (GetFwUuid(uuid))
    {
        wchar_t* ptr = g_uuid_str;
        int i;
        for (i = 0; i < 4; i++) ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (i = 4; i < 6; i++) ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (i = 6; i < 8; i++) ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (i = 8; i < 10; i++) ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (i = 10; i < 16; i++) ptr = hexbyte(uuid[i], ptr);
        *ptr++ = 0;
    }
    else
    {
        wcscpy(g_uuid_str, L"00000000-0000-0000-0000-000000000000");
    }
    DbgPrint("sbie FW-UUID: %S\n", g_uuid_str);
}
