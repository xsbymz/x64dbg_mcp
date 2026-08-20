#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <winternl.h>
using json = nlohmann::json;

namespace handlers {
void register_uefi_runtime_services_routes(c_http_router& router) {

    router.post("/api/uefi/dump_runtime_table", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["note"] = "EFI Runtime Services Table: global function pointer table at EFI_SYSTEM_TABLE.RuntimeServices. Bootkits patch GetVariable/SetVariable to persist across OS reinstall.";
        result["runtime_services"] = {
            {"index",0},{"name","GetTime"},{"index",1},{"name","SetTime"},
            {"index",2},{"name","GetWakeupTime"},{"index",3},{"name","SetWakeupTime"},
            {"index",4},{"name","SetVirtualAddressMap"},{"index",5},{"name","ConvertPointer"},
            {"index",6},{"name","GetVariable — BOOTKIT HOOK TARGET"},
            {"index",7},{"name","GetNextVariableName"},
            {"index",8},{"name","SetVariable — BOOTKIT HOOK TARGET"},
            {"index",9},{"name","GetNextHighMonotonicCount"},
            {"index",10},{"name","ResetSystem"},
            {"index",11},{"name","UpdateCapsule"},
            {"index",12},{"name","QueryCapsuleCapabilities"},
            {"index",13},{"name","QueryVariableInfo"}
        };
        result["known_bootkits"] = {"FinFisher","Lojax","MoonBounce","ESPecter","CosmicStrand"};
        result["detection_method"] = "Read EFI runtime service pointers from physical memory mapped EFI_SYSTEM_TABLE; compare against expected addresses in ntoskrnl!EfiRuntimeServicesBlock or hal.dll";
        result["windows_api"] = "NtQuerySystemInformation(SystemFirmwareTableInformation) with ProviderSignature='RSMB'";
        // Try to get firmware data
        UINT fw = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        result["firmware_table_size"] = fw;
        result["firmware_accessible"] = (fw > 0);
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/uefi/validate_service_pointers", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body=json::object(); }
        json result;
        result["validation_approach"] = {
            {"step1","Locate EFI_RUNTIME_SERVICES table via NtQuerySystemInformation or hal!HalEfiRuntimeServicesBlock"},
            {"step2","Read each function pointer from the table"},
            {"step3","Validate pointer falls within ntoskrnl.exe or hal.dll VA range"},
            {"step4","Flag pointers into anonymous pool allocations or non-signed drivers"}
        };
        result["legitimate_ranges"] = {"ntoskrnl.exe","hal.dll","EhStorClass.sys (GetVariable legitimate implementor)"};
        result["hook_indicators"] = {
            "Pointer outside all loaded kernel module ranges",
            "Pointer into POOL_NX_NONPAGED allocation",
            "Trampoline pattern at target: MOV RAX,imm64; JMP RAX"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/uefi/detect_bootkit_hooks", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["bootkit_signatures"] = {
            {"MoonBounce","Patches SmmGetVariable in SMRAM via vulnerable SMM driver; persists in SPI BIOS region"},
            {"Lojax","Overwrites UEFI boot module list; adds rogue DXE driver to BIOS region"},
            {"ESPecter","Patches Windows Boot Manager (bootmgfw.efi) on ESP partition"},
            {"FinFisher","Installs rogue UEFI boot application via SetVariable(BootOrder)"},
            {"CosmicStrand","Infects CSMCORE.dll in BIOS — executes before bootloader"}
        };
        result["detection_vectors"] = {
            "ESP partition integrity check: hash all EFI/ directory files",
            "Secure Boot database (db) contains unexpected signers",
            "UEFI variable BootOrder contains entries not in standard boot configuration",
            "SPI flash BIOS region has unexpected modification (compare against vendor baseline)"
        };
        // Check Secure Boot state via firmware environment
        DWORD secureboot = 0;
        DWORD sz = sizeof(secureboot);
        BOOL got = GetFirmwareEnvironmentVariableW(L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &secureboot, sz);
        result["secure_boot_enabled"] = got ? (secureboot == 1) : false;
        result["secure_boot_readable"] = (got != 0);
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
