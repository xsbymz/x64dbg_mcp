#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_shadow_ssdt_routes(c_http_router& router) {
    router.post("/api/shadow_ssdt/dump_table", [](const s_http_request& req) {
        json result;
        result["service_descriptor_table_shadow"] = {
            {"Index_0", "nt!KeServiceDescriptorTable (ntoskrnl syscalls)"},
            {"Index_1", "win32k!W32pServiceTable (win32k.sys GUI syscalls: NtUser* and NtGdi*)"},
            {"Index_2", "Reserved / IIS (historical)"},
            {"Index_3", "Reserved"}
        };
        result["thread_context_requirement"] = "Shadow SSDT is only mapped in GUI threads (threads attached to a Win32 desktop with Win32Thread != nullptr in _ETHREAD)";
        result["key_win32k_syscalls"] = {
            {"0x1000", "NtUserGetMessage"},
            {"0x1004", "NtUserPostMessage"},
            {"0x1010", "NtUserFindWindowEx"},
            {"0x1015", "NtUserSetWindowsHookEx"},
            {"0x1042", "NtGdiBitBlt"},
            {"0x1096", "NtUserSendInput"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/shadow_ssdt/validate_entries", [](const s_http_request& req) {
        json result;
        result["validation_rules"] = {
            "1. Service table pointer must reside in win32k.sys, win32kbase.sys, or win32kfull.sys .text section",
            "2. Table base must resolve to W32pServiceTable exported symbol",
            "3. Syscall handler offsets in x64 (stored as compact 32-bit offsets relative to table base) must resolve within win32k modules",
            "4. Table limit (NumberOfServices) should match Windows version build spec (~1000-1300 routines)"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/shadow_ssdt/detect_hooks", [](const s_http_request& req) {
        json result;
        result["hook_mechanisms"] = {
            {"Table_Pointer_Swap", "Overwriting KeServiceDescriptorTableShadow[1].ServiceTable pointer"},
            {"Offset_Patching", "Modifying 32-bit compact relative offset in W32pServiceTable array"},
            {"Inline_Prologue_Hook", "Patching beginning of NtUser*/NtGdi* kernel function with JMP to rootkit module"}
        };
        result["impact"] = "Shadow SSDT hooks enable silent keystroke logging, screen scraping, message tampering, and anti-screenshot cloaking";
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

