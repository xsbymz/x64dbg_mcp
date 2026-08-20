#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_driver_object_table_routes(c_http_router& router) {
    router.post("/api/driver_obj/enumerate_all", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["driver_directory"] = "\\Driver";
        result["key_windows_drivers"] = {
            {"\\Driver\\Disk", "Storage driver handling disk block requests"},
            {"\\Driver\\Ntfs", "NTFS filesystem driver"},
            {"\\Driver\\Tcpip", "Network protocol stack"},
            {"\\Driver\\KsecDD", "Kernel security cryptography provider"},
            {"\\Driver\\Null", "Null and zero device driver"},
            {"\\Driver\\Beep", "Legacy beep driver frequently abused for signed BYOVD"}
        };
        result["driver_object_fields"] = {
            {"Type", "IO_TYPE_DRIVER (0x04)"},
            {"DriverSize", "Size of driver binary in bytes"},
            {"DriverSection", "Pointer to _LDR_DATA_TABLE_ENTRY in kernel PsLoadedModuleList"},
            {"DriverExtension", "Contains AddDevice and ServiceKeyName"},
            {"DeviceObject", "Head of DEVICE_OBJECT linked list created by this driver"},
            {"MajorFunction", "Array of 28 IRP dispatch routines (IRP_MJ_CREATE through IRP_MJ_PNP)"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/driver_obj/dump_major_function_table", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["major_function_indices"] = {
            {"0x00", "IRP_MJ_CREATE"},
            {"0x01", "IRP_MJ_CREATE_NAMED_PIPE"},
            {"0x02", "IRP_MJ_CLOSE"},
            {"0x03", "IRP_MJ_READ"},
            {"0x04", "IRP_MJ_WRITE"},
            {"0x05", "IRP_MJ_QUERY_INFORMATION"},
            {"0x06", "IRP_MJ_SET_INFORMATION"},
            {"0x0E", "IRP_MJ_DEVICE_CONTROL (Core IOCTL dispatch entry)"},
            {"0x0F", "IRP_MJ_INTERNAL_DEVICE_CONTROL"},
            {"0x10", "IRP_MJ_SHUTDOWN"},
            {"0x12", "IRP_MJ_CLEANUP"},
            {"0x1B", "IRP_MJ_PNP"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/driver_obj/detect_dispatch_hooks", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["dispatch_hook_detection_rules"] = {
            "1. MajorFunction[i] must point inside the address bounds [DriverStart, DriverStart + DriverSize]",
            "2. If MajorFunction[i] points to a different driver (e.g. filter driver or rootkit), flag cross-driver dispatch hijack",
            "3. If MajorFunction[i] points to non-paged pool or unallocated memory, flag inline rootkit hook",
            "4. Check for prologue trampolines (0xE9 JMP or 0x48 0xB8 MOV RAX, imm64; JMP RAX) at dispatch routine entry"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
