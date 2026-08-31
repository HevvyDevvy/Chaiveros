#include <ntddk.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\logs\\encryption_keys.log"
#define ALERT_THRESHOLD 5

static int key_creation_count = 0;
UNICODE_STRING log_file_name;
HANDLE log_file_handle = NULL;

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
    LARGE_INTEGER current_time;
    KeQuerySystemTime(&current_time);
    RtlStringCchPrintfW(log_entry, sizeof(log_entry) / sizeof(WCHAR),
                         L"PID: %lu | Key Created: %ws | Timestamp: %lld\r\n",
                         HandleToULong(PsGetProcessId(process)), key, current_time.QuadPart);

    size_t entry_chars = 0;
    RtlStringCchLengthW(log_entry, sizeof(log_entry) / sizeof(WCHAR), &entry_chars);

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
