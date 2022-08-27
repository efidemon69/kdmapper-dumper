#pragma once
#include "types.h"
#include "driver_util.h"

namespace callback
{
    void on_image_load(
        PUNICODE_STRING image_path,
        HANDLE pid,
        PIMAGE_INFO image_info
    );
}