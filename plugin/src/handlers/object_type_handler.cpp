#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_object_type_routes(c_http_router& router) {
    router.post("/api/obj_type/enumerate_types", [](const s_http_request& req) {
        json result;
        result["standard_kernel_object_types"] = {
            {"Type", 1, "Type object itself"},
            {"Directory", 2, "Object directory (e.g. \\KnownDlls, \\Device)"},
            {"SymbolicLink", 3, "DosDevices symlink mapping"},
            {"Process", 7, "_EPROCESS creation and security"},
            {"Thread", 8, "_ETHREAD execution context"},
            {"Job", 9, "Process group management and container constraints"},
            {"Event", 10, "KEVENT synchronization"},
            {"Mutant", 11, "KMUTANT mutex primitive"},
            {"Section", 15, "Memory mapped file/section object"},
            {"File", 28, "IO_FILE_OBJECT filesystem stream"},
            {"Driver", 32, "DRIVER_OBJECT module instance"},
            {"Device", 33, "DEVICE_OBJECT endpoint for I/O requests"},
            {"ALPC_Port", 39, "Inter-process ALPC communication channel"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/obj_type/dump_type_procedures", [](const s_http_request& req) {
        json result;
        result["type_initializer_procedures"] = {
            {"DumpProcedure", "Called when object is formatted or written to memory dump"},
            {"OpenProcedure", "Called on ObOpenObjectByName / ObOpenObjectByPointer to validate access"},
            {"CloseProcedure", "Invoked upon handle closure before reference decrement"},
            {"DeleteProcedure", "Destructor routine called when PointerCount reaches 0"},
            {"ParseProcedure", "Custom name parser (e.g., File, SymbolicLink, RegistryKey)"},
            {"SecurityProcedure", "Custom security descriptor generator / access evaluator"},
            {"QueryNameProcedure", "Retrieves object canonical name for handle inquiries"}
        };
        result["rootkit_hook_target"] = "ParseProcedure & SecurityProcedure hooks in \\ObjectTypes\\Process and \\ObjectTypes\\File enable transparent object hiding from user-mode enumeration";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/obj_type/detect_hooked_procedures", [](const s_http_request& req) {
        json result;
        result["audit_methodology"] = {
            "1. Walk \\ObjectTypes directory in Object Manager namespace",
            "2. Read _OBJECT_TYPE_INITIALIZER function pointer table for each entry",
            "3. Verify all procedure pointers (Dump, Open, Close, Delete, Parse, Security, QueryName) point exclusively into ntoskrnl.exe .text section",
            "4. Flag any pointer outside ntoskrnl.exe as Object Manager Rootkit Hook"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

