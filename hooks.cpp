#include "hooks.h"

namespace hooks
{
    NTSTATUS device_control(
        PDEVICE_OBJECT  device_obj,
        PIRP  irp
    )
    {
        UNREFERENCED_PARAMETER(device_obj);
        PIO_STACK_LOCATION stack_location = IoGetCurrentIrpStackLocation(irp);

        if (stack_location->Parameters.DeviceIoControl.IoControlCode == INTEL_LAN_DRIVER_IOCTL)
        {
            if (stack_location->Parameters.DeviceIoControl.InputBufferLength)
            {
                PCOPY_MEMORY_BUFFER_INFO copy_memory_buffer = reinterpret_cast<PCOPY_MEMORY_BUFFER_INFO>(stack_location->Parameters.SetFile.DeleteHandle);

                //
                // if case is memmove and the destination is in the kernel (pml4 index is > 255)
                //
                if (copy_memory_buffer->case_number == INTEL_LAN_COPY_CASE_NUMBER)
                {
                    if (virt_addr_t{ copy_memory_buffer->destination }.pml4_index > 255)
                    {
                        //
                        // there are a few writes of size 0xC (inline jump code) we can skip those.
                        //
                        if (copy_memory_buffer->length > 0x100)
                        {
                            DBG_PRINT("=============== Dumping Memory ==============");
                            DBG_PRINT(
                                "Copying memory from 0x%p to 0x%p of size 0x%x",
                                copy_memory_buffer->source,
                                copy_memory_buffer->destination,
                                copy_memory_buffer->length
                            );

                            //
                            // dump memory from inside of the calling process to disk.
                            //
                            driver_util::mem_dump(
                                copy_memory_buffer->source,
                                copy_memory_buffer->length
                            );
                        }
                    }
                }
            }
        }
        return reinterpret_cast<decltype(&device_control)>(orig_device_control)(device_obj, irp);
    }
}