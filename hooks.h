#pragma once
#include "types.h"
#include "driver_util.h"

namespace hooks
{
    inline void* orig_device_control = NULL;
    NTSTATUS device_control(
        PDEVICE_OBJECT  device_obj,
        PIRP  irp
    );
}