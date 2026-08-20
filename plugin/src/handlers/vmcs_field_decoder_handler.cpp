#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_vmcs_field_decoder_routes(c_http_router& router) {
    router.post("/api/vmcs_decoder/decode_field_encoding", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        uint32_t encoding = 0;
        std::string encStr = body.value("encoding", "0x00004800");
        try { encoding = std::stoul(encStr, nullptr, 16); } catch(...) { encoding = 0x4800; }

        json result;
        result["encoding_hex"] = encStr;
        uint32_t accessType = encoding & 1; // Bit 0: full vs high
        uint32_t index = (encoding >> 1) & 0x1FF; // Bits 9:1
        uint32_t type = (encoding >> 10) & 0x3; // Bits 11:10
        uint32_t width = (encoding >> 13) & 0x3; // Bits 14:13

        static const char* typeNames[] = { "Control", "VM-Exit Info", "Guest State", "Host State" };
        static const char* widthNames[] = { "16-bit", "64-bit", "32-bit", "Natural-width (32/64-bit)" };

        result["field_type"] = type < 4 ? typeNames[type] : "Unknown";
        result["field_width"] = width < 4 ? widthNames[width] : "Unknown";
        result["field_index"] = index;
        result["access_type"] = accessType == 0 ? "Full 32/64-bit access" : "High 32-bit access";

        return s_http_response::ok(result.dump());;
    });

    router.post("/api/vmcs_decoder/decode_exit_reason", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        uint32_t basicReason = body.value("exit_reason", 10); // 10 = CPUID
        json result;
        result["basic_exit_reason"] = basicReason;

        static const std::unordered_map<uint32_t, std::string> reasonMap = {
            {0, "EXCEPTION_NMI (Hardware exception or NMI)"},
            {1, "EXTERNAL_INTERRUPT (External hardware interrupt)"},
            {2, "TRIPLE_FAULT (Guest triple fault)"},
            {3, "INIT_SIGNAL (INIT signal arrived)"},
            {4, "SIPI (Startup IPI arrived)"},
            {10, "CPUID (Guest executed CPUID instruction)"},
            {18, "VMCALL (Guest executed VMCALL instruction)"},
            {19, "VMCLEAR (Guest executed VMCLEAR instruction)"},
            {20, "VMLAUNCH (Guest executed VMLAUNCH instruction)"},
            {21, "VMPTRLD (Guest executed VMPTRLD instruction)"},
            {22, "VMPTRST (Guest executed VMPTRST instruction)"},
            {23, "VMREAD (Guest executed VMREAD instruction)"},
            {24, "VMRESUME (Guest executed VMRESUME instruction)"},
            {25, "VMWRITE (Guest executed VMWRITE instruction)"},
            {28, "CR_ACCESS (Control register CR0/CR3/CR4/CR8 access)"},
            {29, "DR_ACCESS (Debug register DR0-DR7 access)"},
            {30, "IO_INSTRUCTION (IN, OUT, INS, OUTS access)"},
            {31, "RDMSR (Guest executed RDMSR instruction)"},
            {32, "WRMSR (Guest executed WRMSR instruction)"},
            {48, "EPT_VIOLATION (Guest access violated EPT permissions)"},
            {49, "EPT_MISCONFIG (EPT paging structure misconfiguration)"},
            {55, "XSETBV (Guest executed XSETBV instruction)"}
        };

        auto it = reasonMap.find(basicReason);
        result["reason_name"] = it != reasonMap.end() ? it->second : "UNKNOWN_EXIT_REASON";
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

