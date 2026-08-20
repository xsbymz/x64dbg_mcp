#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_phantom_dll_routes(c_http_router& router) {
    router.post("/api/phantom_dll/scan_unmapped_image_regions", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["phantom_dll_concept"] = {
            "1. Process maps a section object with SEC_IMAGE or SEC_IMAGE_NO_EXECUTE",
            "2. Modifies memory permissions to PAGE_EXECUTE_READ without registering with LdrpLoadDll",
            "3. VirtualQueryEx reports Type == MEM_IMAGE (looks like a loaded DLL)",
            "4. However, the image does NOT appear in PEB.Ldr module linked lists or EDR image load notifications",
            "5. Evades kernel PsSetCreateProcessNotifyRoutine / PsSetLoadImageNotifyRoutine callbacks"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/phantom_dll/compare_against_ldr_list", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["detection_methodology"] = {
            "1. Enumerate all memory regions via VirtualQueryEx where State == MEM_COMMIT and Type == MEM_IMAGE",
            "2. Enumerate all modules in PEB.InLoadOrderModuleList via Toolhelp32 / EnumProcessModules",
            "3. For each MEM_IMAGE region: verify BaseAddress matches DllBase of a known module entry",
            "4. Any MEM_IMAGE region missing from Ldr list is flagged as a Phantom / Unlinked DLL"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/phantom_dll/detect_sec_image_no_execute", [](const s_http_request& req) {
        json result;
        result["techniques"] = {
            {"Transacted_Hollowing", "Creates section from transacted NTFS file (TxF), rolls back transaction, maps image"},
            {"Ghosting", "Creates file with DELETE access, sets deletion disposition, writes payload, creates section, closes file"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

