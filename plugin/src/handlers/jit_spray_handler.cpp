#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_jit_spray_routes(c_http_router& router) {
    router.post("/api/jit_spray/scan_jit_regions", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["jit_spray_mechanism"] = {
            "1. Attacker writes JavaScript / ActionScript arithmetic expressions with large immediate constants (e.g. 0x3C909090)",
            "2. JIT compiler (V8, SpiderMonkey, ChakraCore) emits constant integers directly into JIT code stream (e.g. MOV EAX, 0x3C909090)",
            "3. Jumping into the middle of the MOV instruction (1-byte displacement) executes the immediate values as x86/x64 shellcode",
            "4. Completely bypasses DEP / W^X protections because memory was legitimately marked executable by the JIT engine"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/jit_spray/detect_embedded_shellcode", [](const s_http_request& req) {
        json result;
        result["detection_signatures"] = {
            "Repeated MOV RAX/RCX, imm64 instructions where imm64 decomposes into valid ROP gadgets or syscall stubs",
            "Unusual concentration of XOR, ADD, SUB operations with 4-byte/8-byte constants in JIT page blocks",
            "Disalignment analysis: decoding instructions starting at offset +1, +2, +3 inside JIT basic blocks"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/jit_spray/analyze_immediate_byte_patterns", [](const s_http_request& req) {
        json result;
        result["mitigation_techniques"] = {
            {"Constant_Blinding", "JIT compiler XORs immediate constants with random key at runtime before loading into register"},
            {"Instruction_Nop_Padding", "Inserting random NOP padding between JIT instructions to disrupt sprayed gadget offsets"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

