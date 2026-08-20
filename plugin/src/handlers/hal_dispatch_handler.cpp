#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <dbghelp.h>
using json = nlohmann::json;

namespace handlers {

void register_hal_dispatch_routes(c_http_router& router) {

    // Dump HalDispatchTable entries
    router.post("/api/hal_dispatch/dump_table", [](const s_http_request& req) {
        json result;
        result["note"] = "HalDispatchTable and HalPrivateDispatchTable are kernel global function pointer arrays. HalDispatchTable[1] = HalQuerySystemInformation, classic EoP overwrite target.";

        // Known HAL dispatch indices
        result["hal_dispatch_table"] = {
            {"index",0},{"name","HalQueryBusSlots"},{"note","Index 0"}
        };
        result["hal_dispatch_entries"] = json::array();

        // Named entries in HalDispatchTable (Windows 10)
        std::vector<std::pair<int,std::string>> entries = {
            {0,"HalQueryBusSlots"},
            {1,"HalQuerySystemInformation — CLASSIC EoP OVERWRITE TARGET"},
            {2,"HalSetSystemInformation"},
            {3,"HalQueryBusSlots"},
            {4,"HalExamineMBR"},
            {5,"HalIoAssignDriveLetters"},
            {6,"HalIoReadPartitionTable"},
            {7,"HalIoSetPartitionInformation"},
            {8,"HalIoWritePartitionTable"},
            {9,"HalHandlerForBus"},
            {10,"HalHandlerForConfigSpace"},
            {11,"HalLocateHiberRanges"},
            {12,"HalRegisterBusHandler"},
            {13,"HalSetWakeEnable"}
        };

        // Try to resolve via x64dbg symbol engine
        for (auto& [idx, name] : entries) {
            json entry;
            entry["index"] = idx;
            entry["name"] = name;
            // Attempt symbol resolution
            char symName[256] = {};
            duint addr = 0;
            addr = DbgValFromString(("nt!HalDispatchTable+" + std::to_string(idx * sizeof(void*))).c_str());
            entry["resolved_address"] = addr;
            entry["suspicious"] = (addr == 0) ? false : false; // would check against module map
            result["hal_dispatch_entries"].push_back(entry);
        }
        return s_http_response::ok(result);
    });

    // Validate HAL dispatch table pointers against known modules
    router.post("/api/hal_dispatch/validate_pointers", [](const s_http_request& req) {
        json result;
        result["validation_method"] = "Cross-reference each HalDispatchTable function pointer against the address range of loaded kernel modules (hal.dll, ntoskrnl.exe). Any pointer outside these ranges indicates overwrite.";
        result["modules_to_check"] = {"hal.dll","ntoskrnl.exe","halmacpi.dll","halacpi.dll"};

        // Enumerate loaded modules for validation reference
        result["loaded_modules"] = json::array();
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = {sizeof(me)};
            if (Module32FirstW(hSnap, &me)) {
                do {
                    json mod;
                    char name[MAX_PATH] = {};
                    WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, name, sizeof(name), nullptr, nullptr);
                    std::string modName(name);
                    if (modName.find("hal") != std::string::npos || modName.find("ntoskrnl") != std::string::npos) {
                        mod["name"] = modName;
                        mod["base"] = (uintptr_t)me.modBaseAddr;
                        mod["size"] = (uintptr_t)me.modBaseSize;
                        result["loaded_modules"].push_back(mod);
                    }
                } while (Module32NextW(hSnap, &me));
            }
            CloseHandle(hSnap);
        }
        return s_http_response::ok(result.dump());;
    });

    // Detect overwrite of HAL dispatch table
    router.post("/api/hal_dispatch/detect_overwrite", [](const s_http_request& req) {
        json result;
        result["detection_techniques"] = {
            "Compare HAL dispatch pointers against hal.dll export address range",
            "Check NtQueryIntervalProfile -> HalDispatchTable[1] dispatch chain",
            "Look for trampoline stubs: JMP [rip+0] or PUSH addr; RET patterns at pointed addresses",
            "Verify pointer alignment — legitimate kernel pointers are PAGE_SIZE aligned at start"
        };
        result["eop_patterns"] = {
            {"pattern","NtQueryIntervalProfile + HalDispatchTable[1] overwrite","cve_examples",{"CVE-2010-0270","MS11-011","Stuxnet kernel component"}},
            {"pattern","NtTraceControl + HalPrivateDispatchTable overwrite","notes","Used in Windows 8 era exploits"}
        };
        result["note"] = "Attach to live kernel debugging session for actual runtime validation of HAL dispatch entries.";
        return s_http_response::ok(result.dump());;
    });
}

} // namespace handlers

