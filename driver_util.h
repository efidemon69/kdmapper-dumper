#pragma once
#include "types.h"

namespace driver_util
{
	void* get_driver_base(const char* module_name);
	void* iat_hook(void* base_addr, const char* import, void* func_addr);
	void mem_dump(void* base_addr, unsigned len);
	void* get_kmode_export(const char* mod_name, const char* proc_name);
	void copy_driver(PUNICODE_STRING image_path);
	PDRIVER_OBJECT get_drv_obj(PUNICODE_STRING driver_name);
	PIMAGE_FILE_HEADER get_file_header(void* base_addr);
}