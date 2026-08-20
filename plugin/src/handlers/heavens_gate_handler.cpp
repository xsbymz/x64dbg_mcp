#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_heavens_gate_routes(c_http_router& router) {
    router.post("/api/heavens_gate/detect_far_jumps", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["heavens_gate_architecture"] = {
            {"Concept", "32-bit WOW64 processes switch to 64-bit mode by executing a far jump/call to CS segment 0x33"},
            {"Opcode_Pattern_1", "EA [offset 4-bytes] 33 00 (JMP FAR 0x33:offset)"},
            {"Opcode_Pattern_2", "FF 2D [offset] where pointer target points to CS 0x33"},
            {"Return_Transition", "Switches back to 32-bit compatibility mode using far jump to CS segment 0x23"}
        };
        result["evasion_purpose"] = "Bypasses 32-bit API hooks and user-mode EDR monitoring in 32-bit ntdll.dll by directly executing 64-bit syscalls in 64-bit ntdll.dll";
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/heavens_gate/analyze_wow64_transitions", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["wow64_mechanisms"] = {
            {"Wow64Cpu", "wow64cpu.dll handles normal 32->64 context switching via wow64!Wow64SystemServiceEx"},
            {"Direct_Transition", "Malware constructs direct far call (CALL 0x33:addr), bypassing wow64cpu.dll entirely"},
            {"TEB64_Access", "Reads 64-bit TEB at FS:[0x18] (via 64-bit mode) or WOW64 TEB64 offset to parse 64-bit PEB"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/heavens_gate/scan_for_direct_syscalls", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["detection_pattern"] = "Scan process memory for 64-bit SYSCALL instruction (0x0F 0x05) residing inside 32-bit WOW64 process memory regions";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
