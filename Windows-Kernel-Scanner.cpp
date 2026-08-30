#include <ntddk.h>

#define LOG_FILE L"\\??\\C:\\logs\\encryption_keys.log"
#define ALERT_THRESHOLD 5

static int key_creation_count = 0;
UNICODE_STRING log_file_name;
HANDLE log_file_handle = NULL;

void log_key_creation(PEPROCESS process, const WCHAR* key) {
    if (log_file_handle == NULL) {
        ZwCreateFile(&log_file_handle, GENERIC_WRITE, NULL, NULL,
                     FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, 0);
    }

    WCHAR log_entry[256];
    LARGE_INTEGER current_time;
    KeQuerySystemTime(&current_time);
    RtlStringCchPrintfW(log_entry, sizeof(log_entry)/sizeof(WCHAR), 
                        L"PID: %d | Key Created: %ws | Timestamp: %lld\n",
                        PsGetProcessId(process), key, current_time.QuadPart);

    ZwWriteFile(log_file_handle, NULL, NULL, NULL, NULL, log_entry, 
                sizeof(log_entry), NULL, NULL);
    
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
    RtlInitUnicodeString(&log_file_name, LOG_FILE);
    DbgPrint("Encryption Scanner Loaded\n");
    return STATUS_SUCCESS;
}

extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    if (log_file_handle) {
        ZwClose(log_file_handle);
    }
    DbgPrint("Encryption Scanner Unloaded\n");
}