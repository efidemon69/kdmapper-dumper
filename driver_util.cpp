#include "driver_util.h"

namespace driver_util
{
    void* get_driver_base(const char* module_name)
    {
        ULONG bytes{};
        NTSTATUS status = ZwQuerySystemInformation(
            SystemModuleInformation,
            NULL,
            bytes,
            &bytes
        );

        if (!bytes)
            return NULL;
        PRTL_PROCESS_MODULES modules =
            (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bytes);

        if (modules)
        {
            status = ZwQuerySystemInformation(
                SystemModuleInformation,
                modules,
                bytes,
                &bytes
            );

            if (!NT_SUCCESS(status))
            {
                ExFreePool(modules);
                return NULL;
            }

            PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
            PVOID module_base{}, module_size{};
            for (ULONG i = 0; i < modules->NumberOfModules; i++)
            {
                if (strcmp(reinterpret_cast<char*>(module[i].FullPathName + module[i].OffsetToFileName), module_name) == 0)
                {
                    module_base = module[i].ImageBase;
                    module_size = (PVOID)module[i].ImageSize;
                    break;
                }
            }
            ExFreePool(modules);
            return module_base;
        }
        return NULL;
    }

    void* get_kmode_export(const char* mod_name, const char* proc_name)
    {
        if (!mod_name || !proc_name)
            return NULL;

        void* result = get_driver_base(mod_name);
        if (!result)
            return NULL;
        return RtlFindExportedRoutineByName(result, proc_name);
    }

    PIMAGE_FILE_HEADER get_file_header(void* base_addr)
    {
        if (!base_addr || *(short*)base_addr != 0x5A4D)
            return NULL;

        PIMAGE_DOS_HEADER dos_headers =
            reinterpret_cast<PIMAGE_DOS_HEADER>(base_addr);

        PIMAGE_NT_HEADERS nt_headers =
            reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<DWORD_PTR>(base_addr) + dos_headers->e_lfanew);

        return &nt_headers->FileHeader;
    }

    void* iat_hook(void* base_addr, const char* import, void* func_addr)
    {
        if (!base_addr || *(short*)base_addr != 0x5A4D || !import || !func_addr)
            return NULL;

        PIMAGE_DOS_HEADER dos_headers =
            reinterpret_cast<PIMAGE_DOS_HEADER>(base_addr);

        PIMAGE_NT_HEADERS nt_headers =
            reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<DWORD_PTR>(base_addr) + dos_headers->e_lfanew);

        IMAGE_DATA_DIRECTORY import_dir =
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        PIMAGE_IMPORT_DESCRIPTOR import_des =
            reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(import_dir.VirtualAddress + (DWORD_PTR)base_addr);

        LPCSTR lib_name = NULL;
        PVOID result = NULL;
        PIMAGE_IMPORT_BY_NAME func_name = NULL;

        if (!import_des)
            return NULL;

        while (import_des->Name != NULL)
        {
            lib_name = (LPCSTR)import_des->Name + (DWORD_PTR)base_addr;

            if (get_driver_base(lib_name))
            {
                PIMAGE_THUNK_DATA org_first_thunk = NULL, first_thunk = NULL;
                org_first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)base_addr + import_des->OriginalFirstThunk);
                first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)base_addr + import_des->FirstThunk);
                while (org_first_thunk->u1.AddressOfData != NULL)
                {
                    func_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)base_addr + org_first_thunk->u1.AddressOfData);
                    if (strcmp(func_name->Name, import) == 0)
                    {
                        // save old function pointer
                        result = reinterpret_cast<PVOID>(first_thunk->u1.Function);

                        //
                        // although disabling wp bit can cause crashes, im disabling it for nano seconds. only to write 8 bytes...
                        // in reality this is 1 mov instruction.
                        //
                        {
                            //
                            // disable write protection
                            //
                            _disable();
                            auto cr0 = __readcr0();
                            cr0 &= 0xfffffffffffeffff;
                            __writecr0(cr0);
                        }

                        // swap address
                        first_thunk->u1.Function = reinterpret_cast<ULONG64>(func_addr);
                        
                        {
                            //
                            // enable write protection
                            //
                            auto cr0 = __readcr0();
                            cr0 |= 0x10000;
                            __writecr0(cr0);
                            _enable();
                        }
                        return result;
                    }
                    ++org_first_thunk;
                    ++first_thunk;
                }
            }
            ++import_des;
        }
        return NULL;
    }

    PDRIVER_OBJECT get_drv_obj(PUNICODE_STRING driver_name)
    {
        HANDLE handle{};
        OBJECT_ATTRIBUTES attributes{};
        UNICODE_STRING directory_name{};
        PVOID directory{};
        BOOLEAN success = FALSE;

        RtlInitUnicodeString(&directory_name, L"\\Driver");
        InitializeObjectAttributes(
            &attributes,
            &directory_name,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL
        );

        // open OBJECT_DIRECTORY for \\Driver
        auto status = ZwOpenDirectoryObject(
            &handle,
            DIRECTORY_ALL_ACCESS,
            &attributes
        );

        if (!NT_SUCCESS(status))
        {
            DBG_PRINT("ZwOpenDirectoryObject Failed");
            return NULL;
        }

        // Get OBJECT_DIRECTORY pointer from HANDLE
        status = ObReferenceObjectByHandle(
            handle,
            DIRECTORY_ALL_ACCESS,
            nullptr,
            KernelMode,
            &directory,
            nullptr
        );

        if (!NT_SUCCESS(status))
        {
            DBG_PRINT("ObReferenceObjectByHandle Failed");
            ZwClose(handle);
            return NULL;
        }

        const auto directory_object = POBJECT_DIRECTORY(directory);
        if (!directory_object)
            return NULL;

        ExAcquirePushLockExclusiveEx(&directory_object->Lock, 0);

        // traverse hash table with 37 entries
        // when a new object is created, the object manager computes a hash value in the range zero to 36 from the object name and creates an OBJECT_DIRECTORY_ENTRY.    
        // http://www.informit.com/articles/article.aspx?p=22443&seqNum=7
        for (auto entry : directory_object->HashBuckets)
        {
            if (!entry)
                continue;

            while (entry && entry->Object)
            {
                auto driver = PDRIVER_OBJECT(entry->Object);
                if (!driver)
                    continue;

                if (wcscmp(driver->DriverExtension->ServiceKeyName.Buffer, driver_name->Buffer) == 0)
                    return driver;
                    
                entry = entry->ChainLink;
            }
        }

        ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
        // Release the acquired resources back to the OS
        ObDereferenceObject(directory);
        ZwClose(handle);
        //TODO remove
        return NULL;
    }

    void copy_driver(PUNICODE_STRING image_path)
    {
        HANDLE                    h_file;
        OBJECT_ATTRIBUTES         attr;
        IO_STATUS_BLOCK           status_block;
        LARGE_INTEGER             offset;
        UNICODE_STRING            name;
        FILE_STANDARD_INFORMATION standard_info;

        RtlZeroMemory(&standard_info, sizeof(standard_info));
        InitializeObjectAttributes(
            &attr,
            image_path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, NULL
        );

        NTSTATUS status = ZwCreateFile(
            &h_file,
            GENERIC_READ,
            &attr,
            &status_block,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            NULL,
            FILE_OPEN_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            NULL
        );

        ZwQueryInformationFile(
            h_file,
            &status_block,
            &standard_info,
            sizeof(FILE_STANDARD_INFORMATION),
            FileStandardInformation
        );

        void* drv_buffer = ExAllocatePool(
            NonPagedPool,
            standard_info.AllocationSize.QuadPart
        );

        status = ZwReadFile(
            h_file,
            NULL,
            NULL,
            NULL,
            &status_block,
            drv_buffer,
            standard_info.AllocationSize.QuadPart,
            &offset,
            NULL
        );

        RtlInitUnicodeString(&name, L"\\DosDevices\\C:\\last_load_drv.sys");
        InitializeObjectAttributes(&attr, &name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, NULL
        );

        ZwCreateFile(
            &h_file,
            GENERIC_WRITE,
            &attr,
            &status_block,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            NULL,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            NULL
        );

        ZwWriteFile(
            h_file,
            NULL,
            NULL,
            NULL,
            &status_block,
            drv_buffer,
            standard_info.AllocationSize.QuadPart,
            &offset,
            NULL
        );

        ZwClose(h_file);
        ExFreePool(drv_buffer);
    }

    void mem_dump(void* base_addr, unsigned len)
    {
        if (!base_addr || !len)
            return;

        HANDLE             h_file;
        UNICODE_STRING     name;
        OBJECT_ATTRIBUTES  attr;
        IO_STATUS_BLOCK    status_block;
        LARGE_INTEGER      offset{ NULL };

        RtlInitUnicodeString(&name, L"\\DosDevices\\C:\\dump.bin");
        InitializeObjectAttributes(&attr, &name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, NULL
        );

        auto status = ZwCreateFile(
            &h_file,
            GENERIC_WRITE,
            &attr,
            &status_block,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            NULL,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            NULL
        );

        status = ZwWriteFile(
            h_file,
            NULL,
            NULL,
            NULL,
            &status_block,
            base_addr,
            len,
            &offset,
            NULL
        );
        ZwClose(h_file);
    }
}