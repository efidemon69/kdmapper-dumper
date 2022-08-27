#include "types.h"
#include "callback.h"

void driver_unload(
    DRIVER_OBJECT* driver_obj
)
{
    UNREFERENCED_PARAMETER(driver_obj);
    PsRemoveLoadImageNotifyRoutine(&callback::on_image_load);
}

NTSTATUS driver_close(
    IN PDEVICE_OBJECT  device_obj,
    IN PIRP  lp_irp
)
{
    UNREFERENCED_PARAMETER(device_obj);
    lp_irp->IoStatus.Status = STATUS_SUCCESS;
    lp_irp->IoStatus.Information = NULL;
    IoCompleteRequest(lp_irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
// This driver is not to be manually mapped in its current form.
// If you choose to manually map this driver please remove "driver_close" and "driver_unload".
//
NTSTATUS __cdecl driver_entry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING reg_path
)
{
    UNREFERENCED_PARAMETER(reg_path);
    driver_obj->MajorFunction[IRP_MJ_CLOSE] = &driver_close;
    driver_obj->DriverUnload = &driver_unload;

    DBG_PRINT("callbacks registered, waiting for intel lan driver....");
    return PsSetLoadImageNotifyRoutine(&callback::on_image_load);
}