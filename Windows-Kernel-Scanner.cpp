#include <ntddk.h>

#define LOG_FILE L"\\??\\C:\\logs\\encryption_keys.log"
#define ALERT_THRESHOLD 5

static int key_creation_count = 0;
UNICODE_STRING log_file_name;
HANDLE log_file_handle = NULL;

// Minimal, dependency-free helpers to build the log line.
// Deliberately avoid ntstrsafe.h and any printf-family call: the kernel
// build has no reliable prebuilt ntstrsafe.lib to link against, and the
// header's inline fallback path pulls in a UCRT symbol
// (__stdio_common_vswprintf) that isn't resolvable in a kernel binary.
// wcslen/wcscpy-style loops below compile to plain code under /kernel —
// no external symbols, nothing to link.

static WCHAR* AppendWStr(WCHAR* dst, const WCHAR* end, const WCHAR* src) {
    while (*src && dst < end) { *dst++ = *src++; }
    return dst;
}

static WCHAR* AppendULong(WCHAR* dst, const WCHAR* end, ULONG value) {
    WCHAR tmp[16];
    int n = 0;
    if (value == 0) { if (dst < end) *dst++ = L'0'; return dst; }
    while (value > 0 && n < 16) { tmp[n++] = L'0' + (WCHAR)(value % 10); value /= 10; }
    while (n > 0 && dst < end) { *dst++ = tmp[--n]; }
    return dst;
}

static WCHAR* AppendLongLong(WCHAR* dst, const WCHAR* end, LONGLONG value) {
    if (value < 0) { if (dst < end) *dst++ = L'-'; value = -value; }
    WCHAR tmp[24];
    int n = 0;
    if (value == 0) { if (dst < end) *dst++ = L'0'; return dst; }
    while (value > 0 && n < 24) { tmp[n++] = L'0' + (WCHAR)(value % 10); value /= 10; }
    while (n > 0 && dst < end) { *dst++ = tmp[--n]; }
    return dst;
}

void log_key_creation(PEPROCESS process, const WCHAR* key) {
    if (log_file_handle == NULL) {
        OBJECT_ATTRIBUTES object_attributes;
        IO_STATUS_BLOCK io_status_block;

        InitializeObjectAttributes(&object_attributes, &log_file_name,
                                    OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                    NULL, NULL);

        NTSTATUS create_status = ZwCreateFile(&log_file_handle,
                                               FILE_APPEND_DATA,
                                               &object_attributes,
                                               &io_status_block,
                                               NULL,
                                               FILE_ATTRIBUTE_NORMAL,
                                               FILE_SHARE_READ,
                                               FILE_OPEN_IF,
                                               FILE_SYNCHRONOUS_IO_NONALERT,
                                               NULL,
                                               0);

        if (!NT_SUCCESS(create_status)) {
            DbgPrint("Encryption Scanner: failed to open log file (0x%X)\n", create_status);
            log_file_handle = NULL;
            return;
        }
    }

    WCHAR log_entry[256];
    const WCHAR* log_entry_end = log_entry + (sizeof(log_entry) / sizeof(WCHAR)) - 1; // reserve room for NUL
    LARGE_INTEGER current_time;
    KeQuerySystemTime(&current_time);

    WCHAR* p = log_entry;
    p = AppendWStr(p, log_entry_end, L"PID: ");
    p = AppendULong(p, log_entry_end, HandleToULong(PsGetProcessId(process)));
    p = AppendWStr(p, log_entry_end, L" | Key Created: ");
    p = AppendWStr(p, log_entry_end, key);
    p = AppendWStr(p, log_entry_end, L" | Timestamp: ");
    p = AppendLongLong(p, log_entry_end, current_time.QuadPart);
    p = AppendWStr(p, log_entry_end, L"\r\n");
    *p = L'\0';

    size_t entry_chars = p - log_entry;

    IO_STATUS_BLOCK write_status_block;
    ZwWriteFile(log_file_handle, NULL, NULL, NULL, &write_status_block,
                log_entry, (ULONG)(entry_chars * sizeof(WCHAR)), NULL, NULL);

    key_creation_count++;
    if (key_creation_count > ALERT_THRESHOLD) {
        DbgPrint("Alert: More than %d encryption keys created!\n", ALERT_THRESHOLD);
        // Add alerting mechanisms (e.g., send to SIEM)
    }
}

void MonitorKeyCreation(PEPROCESS process) {
    WCHAR dummy_key[] = L"dummy_key"; // Placeholder
    log_key_creation(process, dummy_key);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&log_file_name, LOG_FILE);
    DbgPrint("Encryption Scanner Loaded\n");
    return STATUS_SUCCESS;
}

extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    if (log_file_handle) {
        ZwClose(log_file_handle);
        log_file_handle = NULL;
    }
    DbgPrint("Encryption Scanner Unloaded\n");
}
