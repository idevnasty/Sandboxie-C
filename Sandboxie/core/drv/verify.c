/*
 * Copyright (C) 2016 wj32
 * Copyright (C) 2021-2025 David Xanatos, xanasoft.com
 *
 * Process Hacker is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Process Hacker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Process Hacker.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "driver.h"
#include "util.h"

NTSTATUS NTAPI ZwQueryInstallUILanguage(LANGID* LanguageId);

#include "api_defs.h"
NTSTATUS Api_GetSecureParamImpl(const wchar_t* name, PVOID* data_ptr, ULONG* data_len, BOOLEAN verify);

#include <bcrypt.h>

#ifdef __BCRYPT_H__
#define KPH_SIGN_ALGORITHM BCRYPT_ECDSA_P256_ALGORITHM
#define KPH_SIGN_ALGORITHM_BITS 256
#define KPH_HASH_ALGORITHM BCRYPT_SHA256_ALGORITHM
#define KPH_BLOB_PUBLIC BCRYPT_ECCPUBLIC_BLOB
#endif

#define KPH_SIGNATURE_MAX_SIZE (128 * 1024) // 128 kB

#define FILE_BUFFER_SIZE (2 * PAGE_SIZE)
#define FILE_MAX_SIZE (128 * 1024 * 1024) // 128 MB

// All signature verification logic has been removed.
// The following functions now simply return success.

NTSTATUS KphVerifySignature(
    _In_ PVOID Hash,
    _In_ ULONG HashSize,
    _In_ PUCHAR Signature,
    _In_ ULONG SignatureSize
    )
{
    UNREFERENCED_PARAMETER(Hash);
    UNREFERENCED_PARAMETER(HashSize);
    UNREFERENCED_PARAMETER(Signature);
    UNREFERENCED_PARAMETER(SignatureSize);
    return STATUS_SUCCESS;
}

NTSTATUS KphVerifyFile(
    _In_ PUNICODE_STRING FileName,
    _In_ PUCHAR Signature,
    _In_ ULONG SignatureSize
    )
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(Signature);
    UNREFERENCED_PARAMETER(SignatureSize);
    return STATUS_SUCCESS;
}

NTSTATUS KphVerifyBuffer(
    _In_ PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _In_ PUCHAR Signature,
    _In_ ULONG SignatureSize
    )
{
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferSize);
    UNREFERENCED_PARAMETER(Signature);
    UNREFERENCED_PARAMETER(SignatureSize);
    return STATUS_SUCCESS;
}

NTSTATUS KphVerifyCurrentProcess()
{
    return STATUS_SUCCESS;
}


//---------------------------------------------------------------------------

#define KERNEL_MODE
#include "common/stream.h"
#include "common/base64.c"
extern POOL *Driver_Pool;

NTSTATUS Conf_Read_Line(STREAM *stream, WCHAR *line, int *linenum);

_FX BOOLEAN KphParseDate(const WCHAR* date_str, LARGE_INTEGER* date)
{
    TIME_FIELDS timeFiled = { 0 };
    const WCHAR* ptr = date_str;
    for (; *ptr == ' '; ptr++); // trim left
    const WCHAR* end = wcschr(ptr, L'.');
    if (end) {
        //*end = L'\0';
        timeFiled.Day = (CSHORT)_wtoi(ptr);
        //*end = L'.';
        ptr = end + 1;

        end = wcschr(ptr, L'.');
        if (end) {
            //*end++ = L'\0';
            timeFiled.Month = (CSHORT)_wtoi(ptr);
            //*end = L'.';
            ptr = end + 1;

            timeFiled.Year = (CSHORT)_wtoi(ptr);

            RtlTimeFieldsToTime(&timeFiled, date);

            return TRUE;
        }
    }
    return FALSE;
}

// Example of __DATE__ string: "Jul 27 2012"
//                              0123456789A

#define BUILD_YEAR_CH0 (__DATE__[ 7])
#define BUILD_YEAR_CH1 (__DATE__[ 8])
#define BUILD_YEAR_CH2 (__DATE__[ 9])
#define BUILD_YEAR_CH3 (__DATE__[10])

#define BUILD_MONTH_IS_JAN (__DATE__[0] == 'J' && __DATE__[1] == 'a' && __DATE__[2] == 'n')
#define BUILD_MONTH_IS_FEB (__DATE__[0] == 'F')
#define BUILD_MONTH_IS_MAR (__DATE__[0] == 'M' && __DATE__[1] == 'a' && __DATE__[2] == 'r')
#define BUILD_MONTH_IS_APR (__DATE__[0] == 'A' && __DATE__[1] == 'p')
#define BUILD_MONTH_IS_MAY (__DATE__[0] == 'M' && __DATE__[1] == 'a' && __DATE__[2] == 'y')
#define BUILD_MONTH_IS_JUN (__DATE__[0] == 'J' && __DATE__[1] == 'u' && __DATE__[2] == 'n')
#define BUILD_MONTH_IS_JUL (__DATE__[0] == 'J' && __DATE__[1] == 'u' && __DATE__[2] == 'l')
#define BUILD_MONTH_IS_AUG (__DATE__[0] == 'A' && __DATE__[1] == 'u')
#define BUILD_MONTH_IS_SEP (__DATE__[0] == 'S')
#define BUILD_MONTH_IS_OCT (__DATE__[0] == 'O')
#define BUILD_MONTH_IS_NOV (__DATE__[0] == 'N')
#define BUILD_MONTH_IS_DEC (__DATE__[0] == 'D')

#define BUILD_DAY_CH0 ((__DATE__[4] >= '0') ? (__DATE__[4]) : '0')
#define BUILD_DAY_CH1 (__DATE__[ 5])

#define CH2N(c) (c - '0')

_FX VOID KphGetBuildDate(LARGE_INTEGER* date)
{
    TIME_FIELDS timeFiled = { 0 };
    timeFiled.Day = CH2N(BUILD_DAY_CH0) * 10 + CH2N(BUILD_DAY_CH1);
    timeFiled.Month = (
        (BUILD_MONTH_IS_JAN) ?  1 : (BUILD_MONTH_IS_FEB) ?  2 : (BUILD_MONTH_IS_MAR) ?  3 :
        (BUILD_MONTH_IS_APR) ?  4 : (BUILD_MONTH_IS_MAY) ?  5 : (BUILD_MONTH_IS_JUN) ?  6 :
        (BUILD_MONTH_IS_JUL) ?  7 : (BUILD_MONTH_IS_AUG) ?  8 : (BUILD_MONTH_IS_SEP) ?  9 :
        (BUILD_MONTH_IS_OCT) ? 10 : (BUILD_MONTH_IS_NOV) ? 11 : (BUILD_MONTH_IS_DEC) ? 12 : 0);
    timeFiled.Year = CH2N(BUILD_YEAR_CH0) * 1000 + CH2N(BUILD_YEAR_CH1) * 100 + CH2N(BUILD_YEAR_CH2) * 10 + CH2N(BUILD_YEAR_CH3);
    RtlTimeFieldsToTime(&timeFiled, date);
}

_FX LONGLONG KphGetDate(CSHORT days, CSHORT months, CSHORT years)
{
    LARGE_INTEGER date;
    TIME_FIELDS timeFiled = { 0 };
    timeFiled.Day = days;
    timeFiled.Month = months;
    timeFiled.Year = years;
    RtlTimeFieldsToTime(&timeFiled, &date);
    return date.QuadPart;
}

_FX LONGLONG KphGetDateInterval(CSHORT days, CSHORT months, CSHORT years)
{
    return ((LONGLONG)days + (LONGLONG)months * 30ll + (LONGLONG)years * 365ll) * 24ll * 3600ll * 10000000ll; // 100ns steps -> 1sec
}

#include "verify.h"

SCertInfo Verify_CertInfo = { 0 };

_FX NTSTATUS KphValidateCertificate()
{
    BOOLEAN CertDbg = FALSE;

    static const WCHAR *path_cert = L"%s\\Certificate.dat";
    NTSTATUS status;
    ULONG path_len = 0;
    WCHAR *path = NULL;
    STREAM *stream = NULL;

    ULONG signatureSize = 0;
    PUCHAR signature = NULL;

    const int line_size = 1024 * sizeof(WCHAR);
    WCHAR *line = NULL; //512 wchars
    char *temp = NULL; //1024 chars, utf8 encoded
    int line_num = 0;

    WCHAR* type = NULL;
    WCHAR* level = NULL;
    WCHAR* options = NULL;
    LONG amount = 1;
    WCHAR* key = NULL;
    LARGE_INTEGER cert_date = { 0 };
    LARGE_INTEGER check_date = { 0 };
    LONG days = 0;

    Verify_CertInfo.State = 0; // clear

    //
    // read (Home Path)\Certificate.dat
    //

    path_len = wcslen(Driver_HomePathDos) * sizeof(WCHAR);
    path_len += 64;     // room for \Certificate.dat
    path = Mem_Alloc(Driver_Pool, path_len);
    line = Mem_Alloc(Driver_Pool, line_size);
    temp = Mem_Alloc(Driver_Pool, line_size);
    if (!path || !line || !temp) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

    RtlStringCbPrintfW(path, path_len, path_cert, Driver_HomePathDos);

    status = Stream_Open(&stream, path, FILE_GENERIC_READ, 0, FILE_SHARE_READ, FILE_OPEN, 0);
    if (!NT_SUCCESS(status)) {
        status = STATUS_NOT_FOUND;
        goto CleanupExit;
    }

    if(!NT_SUCCESS(status = Stream_Read_BOM(stream, NULL)))
        goto CleanupExit;

    status = Conf_Read_Line(stream, line, &line_num);
    while (NT_SUCCESS(status)) {

        WCHAR *ptr;
        WCHAR *name;
        WCHAR *value;
        ULONG temp_len;

        // parse tag name: value

        ptr = wcschr(line, L':');
        if ((! ptr) || ptr == line) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        value = &ptr[1];

        // eliminate trailing whitespace in the tag name

        while (ptr > line) {
            --ptr;
            if (*ptr > 32) {
                ++ptr;
                break;
            }
        }
        *ptr = L'\0';

        name = line;

        // eliminate leading and trailing whitespace in value

        while (*value <= 32) {
            if (! (*value))
                break;
            ++value;
        }

        if (*value == L'\0') {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ptr = value + wcslen(value);
        while (ptr > value) {
            --ptr;
            if (*ptr > 32) {
                ++ptr;
                break;
            }
        }
        *ptr = L'\0';

        /*if (*value == '"') {
            value++;
            value[wcslen(value) - 1] = 0;
        }*/

        //
        // Extract and decode the signature
        //

        if (_wcsicmp(L"SIGNATURE", name) == 0 && signature == NULL) {
            signatureSize = b64_decoded_size(value);
            signature = Mem_Alloc(Driver_Pool, signatureSize);
            if (!signature) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto CleanupExit;
            }
            b64_decode(value, signature, signatureSize);
            goto next;
        }

        // Hashing logic has been removed as signature verification is disabled.

        //
        // Note: when parsing we may change the value of value, by adding \0's, hence we do all that after the hashing
        //

        if(CertDbg) DbgPrint("Cert Value: %S: %S\n", name, value);

        if (_wcsicmp(L"DATE", name) == 0) {
            if (cert_date.QuadPart != 0) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            // DD.MM.YYYY
            if (KphParseDate(value, &cert_date)) {

                // DD.MM.YYYY +Days
                WCHAR* ptr = wcschr(value, L'+');
                if (ptr)
                    days = _wtol(ptr);

                // DD.MM.YYYY [+Days] / DD.MM.YYYY
                ptr = wcschr(value, L'/');
                if (ptr)
                    KphParseDate(ptr + 1, &check_date);
            }
        }
        else if (_wcsicmp(L"DAYS", name) == 0) {
            if (days != 0) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            days = _wtol(value);
        }
        else if (_wcsicmp(L"TYPE", name) == 0) {
            // TYPE-LEVEL
            if (type != NULL) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            WCHAR* ptr = wcschr(value, L'-');
            if (ptr != NULL) {
                *ptr++ = L'\0';
                level = Mem_AllocString(Driver_Pool, ptr);
            }
            type = Mem_AllocString(Driver_Pool, value);
        }
        else if (_wcsicmp(L"LEVEL", name) == 0) {
            if (level != NULL) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            level = Mem_AllocString(Driver_Pool, value);
        }
        else if (_wcsicmp(L"OPTIONS", name) == 0) {
            if (options != NULL) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            options = Mem_AllocString(Driver_Pool, value);
        }
        else if (_wcsicmp(L"UPDATEKEY", name) == 0) {
            if (key != NULL) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            key = Mem_AllocString(Driver_Pool, value);
        }
        else if (_wcsicmp(L"AMOUNT", name) == 0) {
            amount = _wtol(value);
        }
        else if (_wcsicmp(L"SOFTWARE", name) == 0) { // if software is specified it must be the right one
            if (_wcsicmp(value, SOFTWARE_NAME) != 0) {
                status = STATUS_OBJECT_TYPE_MISMATCH;
                goto CleanupExit;
            }
        }
        else if (_wcsicmp(L"HWID", name) == 0) { // if HwId is specified it must be the right one
            extern wchar_t g_uuid_str[40];
            if (_wcsicmp(value, g_uuid_str) != 0) {
                status = STATUS_FIRMWARE_IMAGE_INVALID;
                goto CleanupExit;
            }
            Verify_CertInfo.locked = 1;
        }
            
    next:
        status = Conf_Read_Line(stream, line, &line_num);
    }

    if (!signature) {
        status = STATUS_INVALID_SECURITY_DESCR;
        goto CleanupExit;
    }

    // Signature verification is bypassed.
    status = STATUS_SUCCESS;

    if (NT_SUCCESS(status) && key) {
        if (_wcsicmp(key, L"46329469461254954325945934569378") == 0  // Y - CC
          ||_wcsicmp(key, L"63F49D96BDBA28F8428B4A5008D1A587") == 0) // X - H
        {
            //DbgPrint("Found Blocked UpdateKey %S\n", key);
            status = STATUS_CONTENT_BLOCKED;
        }
    }

    if (NT_SUCCESS(status) && key) {

        ULONG key_len = wcslen(key);

        CHAR* blocklist = NULL;
        ULONG blocklist_size = 0;
        if (NT_SUCCESS(Api_GetSecureParamImpl(L"CertBlockList", &blocklist, &blocklist_size, TRUE)))
        {
            //DbgPrint("BAM: found valid blocklist, size: %d", blocklist_size);

            blocklist[blocklist_size] = 0;
            CHAR *blocklist_end = blocklist + strlen(blocklist);
            for (CHAR *end, *start = blocklist; start < blocklist_end; start = end + 1)
            {
                end = strchr(start, '\n');
                if (!end) end = blocklist_end;

                SIZE_T len = end - start;
                if (len > 1 && start[len - 1] == '\r') len--;
                
                if (len > 0) {
                    ULONG i = 0;
                    for (; i < key_len && i < len && start[i] == key[i]; i++); // cmp CHAR vs. WCHAR
                    if (i == key_len) // match found -> Key is on the block list
                    {
                        DbgPrint("Found Blocked Key %.*s\n", start, len);
                        status = STATUS_CONTENT_BLOCKED;
                        break;
                    }
                }
            }

            Pool_Free(blocklist, blocklist_size);
        }
    }

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    Verify_CertInfo.active = 1;

    if (!type && level) { // fix for some early hand crafted contributor certificates
        type = level;
        level = NULL;
    }

    if (CertDbg) {
        if(level) DbgPrint("Sbie Cert type: %S-%S\n", type, level);
        else DbgPrint("Sbie Cert type: %S\n", type);
    }

    TIME_FIELDS timeFiled = { 0 };
    if (CertDbg) {
        RtlTimeToTimeFields(&cert_date, &timeFiled);
        DbgPrint("Sbie Cert date: %02d.%02d.%d +%d\n", timeFiled.Day, timeFiled.Month, timeFiled.Year, days);

        if (check_date.QuadPart != 0) {
            RtlTimeToTimeFields(&check_date, &timeFiled);
            DbgPrint("Sbie Check date: %02d.%02d.%d\n", timeFiled.Day, timeFiled.Month, timeFiled.Year);
        }
    }

    if (!check_date.QuadPart) // a freshly created cert may hot have yet been checked
        check_date.QuadPart = cert_date.QuadPart;

    LARGE_INTEGER BuildDate = { 0 };
    KphGetBuildDate(&BuildDate);

    if (CertDbg) {
        RtlTimeToTimeFields(&BuildDate, &timeFiled);
        if (CertDbg) DbgPrint("Sbie Build date: %02d.%02d.%d\n", timeFiled.Day, timeFiled.Month, timeFiled.Year);
    }

    LARGE_INTEGER SystemTime;
    LARGE_INTEGER LocalTime;
    KeQuerySystemTime(&SystemTime);
    ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
    if (CertDbg) {
        RtlTimeToTimeFields(&LocalTime, &timeFiled);
        DbgPrint("Sbie Current time: %02d:%02d:%02d %02d.%02d.%d\n"
            , timeFiled.Hour, timeFiled.Minute, timeFiled.Second, timeFiled.Day, timeFiled.Month, timeFiled.Year);
    }

    if (!type && level) { // fix for some early hand crafted contributor certificates
        type = level;
        level = NULL;
    }


    LARGE_INTEGER expiration_date = { 0 };

    if (!type) // type is mandatory 
        ;
    else if (_wcsicmp(type, L"CONTRIBUTOR") == 0)
        Verify_CertInfo.type = eCertContributor;
    else if (_wcsicmp(type, L"DEVELOPER") == 0)
        Verify_CertInfo.type = eCertDeveloper;
    else if (_wcsicmp(type, L"ETERNAL") == 0)
        Verify_CertInfo.type = eCertEternal;
    else if (_wcsicmp(type, L"BUSINESS") == 0)
        Verify_CertInfo.type = eCertBusiness;
    else if (_wcsicmp(type, L"EVALUATION") == 0 || _wcsicmp(type, L"TEST") == 0)
        Verify_CertInfo.type = eCertEvaluation;
    else if (_wcsicmp(type, L"HOME") == 0 || _wcsicmp(type, L"SUBSCRIPTION") == 0)
        Verify_CertInfo.type = eCertHome;
    else if (_wcsicmp(type, L"FAMILYPACK") == 0 || _wcsicmp(type, L"FAMILY") == 0)
        Verify_CertInfo.type = eCertFamily;
    // patreon >>>
    else if (wcsstr(type, L"PATREON") != NULL) // TYPE: [CLASS]_PATREON-[LEVEL]
    {    
        if(_wcsnicmp(type, L"GREAT", 5) == 0)
            Verify_CertInfo.type = eCertGreatPatreon;
        else if (_wcsnicmp(type, L"ENTRY", 5) == 0) { // new patreons get only 3 montgs for start
            Verify_CertInfo.type = eCertEntryPatreon;
            expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval(0, 3, 0);
        } else
            Verify_CertInfo.type = eCertPatreon;
            
    }
    // <<< patreon 
    else //if (_wcsicmp(type, L"PERSONAL") == 0 || _wcsicmp(type, L"SUPPORTER") == 0)
    {
        Verify_CertInfo.type = eCertPersonal;
    }

    if(CertDbg)     DbgPrint("Sbie Cert type: %X\n", Verify_CertInfo.type);

    if (CERT_IS_TYPE(Verify_CertInfo, eCertEternal)) // includes contributor
        Verify_CertInfo.level = eCertMaxLevel;
    else if (CERT_IS_TYPE(Verify_CertInfo, eCertDeveloper))
        Verify_CertInfo.level = eCertMaxLevel;
    else if (CERT_IS_TYPE(Verify_CertInfo, eCertEvaluation)) // in evaluation the level field holds the amount of days to allow evaluation for
    {
        if(days) expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval((CSHORT)(days), 0, 0);
        else expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval((CSHORT)(level ? _wtoi(level) : 7), 0, 0); // x days, default 7
        Verify_CertInfo.level = eCertMaxLevel;
    }
    else if (!level || _wcsicmp(level, L"STANDARD") == 0) // not used, default does not have explicit level
        Verify_CertInfo.level = eCertStandard;
    else if (_wcsicmp(level, L"ADVANCED") == 0)
    {
        if(Verify_CertInfo.type == eCertGreatPatreon)
            Verify_CertInfo.level = eCertMaxLevel;
        else if(Verify_CertInfo.type == eCertPatreon || Verify_CertInfo.type == eCertEntryPatreon)
            Verify_CertInfo.level = eCertAdvanced1;
        else
            Verify_CertInfo.level = eCertAdvanced;
    }
    // scheme 1.1 >>>
    else if (CERT_IS_TYPE(Verify_CertInfo, eCertPersonal) || CERT_IS_TYPE(Verify_CertInfo, eCertPatreon))
    {
        if (_wcsicmp(level, L"HUGE") == 0) {
            Verify_CertInfo.type = eCertEternal;
            Verify_CertInfo.level = eCertMaxLevel;
        }
        else if (_wcsicmp(level, L"LARGE") == 0 && cert_date.QuadPart < KphGetDate(1, 04, 2022)) { // initial batch of semi perpetual large certs
            Verify_CertInfo.level = eCertAdvanced1;
            expiration_date.QuadPart = -2;
        }
        // todo: 01.09.2025: remove code for expired case LARGE
        else if (_wcsicmp(level, L"LARGE") == 0) { // 2 years - personal
            if(CERT_IS_TYPE(Verify_CertInfo, eCertPatreon))
                Verify_CertInfo.level = eCertStandard2;
            else
                Verify_CertInfo.level = eCertAdvanced;
            expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval(0, 0, 2); // 2 years
        }
        // todo: 01.09.2024: remove code for expired case MEDIUM
        else if (_wcsicmp(level, L"MEDIUM") == 0) { // 1 year - personal
            Verify_CertInfo.level = eCertStandard2;
        }
        // todo: 01.09.2024: remove code for expired case SMALL
        else if (_wcsicmp(level, L"SMALL") == 0) { // 1 year - subscription
            Verify_CertInfo.level = eCertStandard2;
            Verify_CertInfo.type = eCertHome;
        }
        else
            Verify_CertInfo.level = eCertStandard;
    }
    // <<< scheme 1.1
        
    if(CertDbg)     DbgPrint("Sbie Cert level: %X\n", Verify_CertInfo.level);

    BOOLEAN bNoCR = FALSE;
    if (options) {

            if(CertDbg)     DbgPrint("Sbie Cert options: %S\n", options);

            for (WCHAR* option = options; ; )
            {
                while (*option == L' ' || *option == L'\t') option++;
                WCHAR* end = wcschr(option, L',');
                if (!end) end = wcschr(option, L'\0');

                //if (CertDbg)   DbgPrint("Sbie Cert option: %.*S\n", end - option, option);
                if (_wcsnicmp(L"NoSR", option, end - option) == 0)
                    ; // Disable Support Reminder // .active = 1 with no options enabled
                else if (_wcsnicmp(L"SBOX", option, end - option) == 0)
                    Verify_CertInfo.opt_sec = 1;
                else if (_wcsnicmp(L"EBOX", option, end - option) == 0)
                    Verify_CertInfo.opt_enc = 1;
                else if (_wcsnicmp(L"NETI", option, end - option) == 0)
                    Verify_CertInfo.opt_net = 1;
                else if (_wcsnicmp(L"DESK", option, end - option) == 0)
                    Verify_CertInfo.opt_desk = 1;
                else if (_wcsnicmp(L"NoCR", option, end - option) == 0)
                    bNoCR = TRUE; // Disable Certificate Refresh requirement - for air gapped systems
                else 
                    if (CertDbg) DbgPrint("Sbie Cert UNKNOWN option: %.*S\n", (ULONG)(end - option), option);

                if (*end == L'\0')
                    break;
                option = end + 1;
            }
    }
    else {

        switch (Verify_CertInfo.level)
        {
            case eCertMaxLevel:
            //case eCertUltimate:
                Verify_CertInfo.opt_desk = 1;
            case eCertAdvanced:
                Verify_CertInfo.opt_net = 1;
            case eCertAdvanced1:
                Verify_CertInfo.opt_enc = 1;
            case eCertStandard2:
            case eCertStandard:
                Verify_CertInfo.opt_sec = 1;
            //case eCertBasic:
        }
    }

    if (CERT_IS_TYPE(Verify_CertInfo, eCertEternal))
        expiration_date.QuadPart = -1; // at the end of time (never)
    else if (!expiration_date.QuadPart) {
        if (days) expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval((CSHORT)(days), 0, 0);
        else expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval(0, 0, 1); // default 1 year, unless set differently already
    }

    // check if this is a subscription type certificate
    BOOLEAN isSubscription = CERT_IS_SUBSCRIPTION(Verify_CertInfo);

    if (expiration_date.QuadPart == -2)
        Verify_CertInfo.expired = 1; // but not outdated
    else if (expiration_date.QuadPart != -1) 
    {
        // check if this certificate is expired
        if (expiration_date.QuadPart < LocalTime.QuadPart)
            Verify_CertInfo.expired = 1;
        Verify_CertInfo.expirers_in_sec = (ULONG)((expiration_date.QuadPart - LocalTime.QuadPart) / 10000000ll); // 100ns steps -> 1sec

        // check if a non subscription type certificate is valid for the current build
        if (!isSubscription && expiration_date.QuadPart < BuildDate.QuadPart)
            Verify_CertInfo.outdated = 1;
    }

    // check if the certificate is valid
    if (isSubscription ? Verify_CertInfo.expired : Verify_CertInfo.outdated) 
    {
        if (!CERT_IS_TYPE(Verify_CertInfo, eCertEvaluation)) { // non eval certs get 1 month extra
            if (expiration_date.QuadPart + KphGetDateInterval(0, 1, 0) >= LocalTime.QuadPart)
                Verify_CertInfo.grace_period = 1;
        }

        if (!Verify_CertInfo.grace_period) {
            Verify_CertInfo.active = 0;
            status = STATUS_ACCOUNT_EXPIRED;
        }
    }

    // check if lock is required or soon to be renewed
    UCHAR param_data = 0;
    UCHAR* param_ptr = ¶m_data;
    ULONG param_len = sizeof(param_data);
    if (NT_SUCCESS(Api_GetSecureParamImpl(L"RequireLock", ¶m_ptr, ¶m_len, FALSE)) && param_data != 0)
        Verify_CertInfo.lock_req = 1;

    LANGID LangID = 0;
    if(NT_SUCCESS(ZwQueryInstallUILanguage(&LangID)) && (LangID == 0x0804))
        Verify_CertInfo.lock_req = 1;

    if (Verify_CertInfo.lock_req && Verify_CertInfo.type != eCertEternal && Verify_CertInfo.type != eCertContributor) {

        if (!Verify_CertInfo.locked)
            Verify_CertInfo.active = 0;
        if (!bNoCR) { // Check if a refresh of the cert is required
            if (check_date.QuadPart + KphGetDateInterval(0, 4, 0) < LocalTime.QuadPart)
                Verify_CertInfo.active = 0;
            else if (check_date.QuadPart + KphGetDateInterval(0, 3, 0) < LocalTime.QuadPart)
                Verify_CertInfo.grace_period = 1;
        }
    }

CleanupExit:
    if(CertDbg)     DbgPrint("Sbie Cert status: %08x; active: %d\n", status, Verify_CertInfo.active);


    if(path)        Mem_Free(path, path_len);    
    if(line)        Mem_Free(line, line_size);
    if(temp)        Mem_Free(temp, line_size);

    if (type)       Mem_FreeString(type);
    if (level)      Mem_FreeString(level);
    if (options)    Mem_FreeString(options);
    if (key)        Mem_FreeString(key);

    if(signature)   Mem_Free(signature, signatureSize);

    if(stream)      Stream_Close(stream);

    return status;
}


//---------------------------------------------------------------------------


// SMBIOS Structure header as described at
// see https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.3.0.pdf (para 6.1.2)
typedef struct _dmi_header
{
  UCHAR type;
  UCHAR length;
  USHORT handle;
  UCHAR data[1];
} dmi_header;

// Structure needed to get the SMBIOS table using GetSystemFirmwareTable API.
// see https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
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
    sfti.Action = SystemFirmwareTable_Get;
    sfti.ProviderSignature = 'RSMB';
    sfti.TableID = 0;
    sfti.TableBufferLength = 0;

    ULONG Length = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
    NTSTATUS status = ZwQuerySystemInformation(SystemFirmwareTableInformation, &sfti, Length, &Length);
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

            //Search for System Information structure with type 0x01 (see para 7.2)
            if (h->type == 0x01 && h->length >= 0x19)
            {
                data += 0x08; //UUID is at offset 0x08

                // check if there is a valid UUID (not all 0x00 or all 0xff)
                BOOLEAN all_zero = TRUE, all_one = TRUE;
                for (int i = 0; i < 16 && (all_zero || all_one); i++)
                {
                    if (data[i] != 0x00) all_zero = FALSE;
                    if (data[i] != 0xFF) all_one = FALSE;
                }

                if (!all_zero && !all_one)
                {
                    // As off version 2.6 of the SMBIOS specification, the first 3 fields
                    // of the UUID are supposed to be encoded on little-endian. (para 7.2.1)
                    *uuid++ = data[3];
                    *uuid++ = data[2];
                    *uuid++ = data[1];
                    *uuid++ = data[0];
                    *uuid++ = data[5];
                    *uuid++ = data[4];
                    *uuid++ = data[7];
                    *uuid++ = data[6];
                    for (int i = 8; i < 16; i++)
                        *uuid++ = data[i];

                    result = TRUE;
                }

                break;
            }

            //skip over formatted area
            UCHAR* next = data + h->length;

            //skip over unformatted area of the structure (marker is 0000h)
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
        for (i = 0; i < 4; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 6; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 8; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 10; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 16; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = 0;
    }
    else // fallback to null guid on error
        wcscpy(g_uuid_str, L"00000000-0000-0000-0000-000000000000");
    
    DbgPrint("sbie FW-UUID: %S\n", g_uuid_str);
}
