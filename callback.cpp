#include "callback.h"
#include "hooks.h"

namespace callback
{
    NTSTATUS gh_create_device(
        PDRIVER_OBJECT  driver_obj,
        ULONG           device_ext,
        PUNICODE_STRING device_name,
        DEVICE_TYPE     device_type,
        ULONG           device_char,
        BOOLEAN         exclusive,
        PDEVICE_OBJECT* lpdevice_obj
    )
    {
        DBG_PRINT("=============== IoCreateDevice Called ===============");
        DBG_PRINT("     - driver object: 0x%p", driver_obj);

        //
        // swap ioctl pointer
        //
        hooks::orig_device_control = driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &hooks::device_control;

        DBG_PRINT("     - swapped ioctl function from 0x%p to 0x%p", driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL], &hooks::device_control);
        return IoCreateDevice(
            driver_obj,
            device_ext,
            device_name, 
            device_type,
            device_char,
            exclusive, 
            lpdevice_obj
        );
    }

    void on_image_load(
        PUNICODE_STRING image_path,
        HANDLE pid,
        PIMAGE_INFO image_info
    )
    {
        if (!pid)
        {
            DBG_PRINT("driver loaded from: %ws", image_path->Buffer);
            DBG_PRINT("     - driver timestamp: 0x%p", driver_util::get_file_header(image_info->ImageBase)->TimeDateStamp);

            //
            // if its intel lan driver then we hook IoCreateDevice and swap ioctl pointer.
            //
            if (driver_util::get_file_header(image_info->ImageBase)->TimeDateStamp == INTEL_LAN_DRIVER_TIMESTAMP)
            {
                DBG_PRINT("=============== Intel Lan Driver Loaded ===============");
                driver_util::iat_hook(
                    image_info->ImageBase,
                    "IoCreateDevice",
                    &gh_create_device
                );
            }
        }
    }
}