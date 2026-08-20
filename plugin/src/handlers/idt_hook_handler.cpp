#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <intrin.h>
using json = nlohmann::json;

namespace handlers {
void register_idt_hook_routes(c_http_router& router) {

    router.post("/api/idt/dump_table", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body=json::object(); }
        json result;
        // Read IDTR
        struct IDTR { WORD limit; ULONG_PTR base; } __attribute__((packed));
        IDTR idtr = {};
        __sidt(&idtr);
        result["idtr_base"] = idtr.base;
        result["idtr_limit"] = idtr.limit;
        result["gate_count"] = (idtr.limit + 1) / 16; // Each IDT gate = 16 bytes on x64
        result["gates"] = json::array();
        // IDT gate descriptor (x64 Interrupt Gate)
        struct IDT_GATE { WORD off0; WORD sel; BYTE ist; BYTE type; WORD off16; DWORD off32; DWORD reserved; };
        // Security-critical vectors
        static const char* vectorNames[] = {
            "#DE Divide Error","#DB Debug","NMI","#BP Breakpoint",
            "#OF Overflow","#BR BOUND","#UD Invalid Opcode","#NM Device NA",
            "#DF Double Fault","Coprocessor","#TS Invalid TSS","#NP Segment NP",
            "#SS Stack Fault","#GP General Protection","#PF Page Fault","Reserved",
            "#MF x87 FP","#AC Alignment","#MC Machine Check","#XM SIMD FP","#VE Virt Exc"
        };
        if (idtr.base && idtr.limit >= 15) {
            auto* gates = reinterpret_cast<IDT_GATE*>(idtr.base);
            int count = std::min((int)result["gate_count"].get<int>(), 64);
            for (int i = 0; i < count; i++) {
                auto& g = gates[i];
                uintptr_t handler = (uintptr_t)g.off0 | ((uintptr_t)g.off16 << 16) | ((uintptr_t)g.off32 << 32);
                json gate;
                gate["vector"] = i;
                gate["name"] = (i < 21) ? vectorNames[i] : ("INT " + std::to_string(i));
                gate["handler"] = handler;
                gate["ist"] = (g.ist & 7);
                gate["type"] = (g.type & 0xF);
                gate["dpl"] = (g.type >> 5) & 3;
                gate["present"] = (g.type >> 7) & 1;
                result["gates"].push_back(gate);
            }
        }
        result["note"] = "Rootkit-targeted vectors: 0x01 (#DB debug), 0x02 (NMI), 0x03 (#BP int3), 0x0E (#PF page fault). Handlers must point into ntoskrnl.exe or hal.dll range.";
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/idt/validate_gate_handlers", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["validation_approach"] = {
            "Read IDTR base with SIDT instruction",
            "For each gate: extract handler VA = off0 | (off16<<16) | (off32<<32)",
            "Cross-check handler VA against loaded kernel module address ranges",
            "Flag handlers NOT in ntoskrnl.exe or hal.dll"
        };
        result["legitimate_modules"] = {"ntoskrnl.exe","ntkrnlpa.exe","ntkrnlmp.exe","hal.dll","halmacpi.dll"};
        result["hook_techniques"] = {
            {"inline_hook","JMP [rip+0] at handler start — redirects to rootkit stub"},
            {"idt_replacement","Replace entire gate descriptor — change off0/off16/off32"},
            {"ist_manipulation","Change IST field to use different kernel stack — stack pivot"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/idt/detect_hooked_vectors", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["high_value_vectors"] = {
            {"0x00","#DE — used by some packers for anti-debug (div 0 trick)"},
            {"0x01","#DB — single step trap, debug register trap — rootkit favorite"},
            {"0x02","NMI — Non-Maskable Interrupt — bypasses all masking, kernel-mode only"},
            {"0x03","#BP — INT3 breakpoint — critical for debugger interaction"},
            {"0x0D","#GP — General Protection — used for privileged instruction emulation"},
            {"0x0E","#PF — Page Fault — hooked by memory forensic rootkits to hide pages"},
            {"0x2E","INT 2E — legacy syscall (Windows 2000 era), still present in ntdll"},
            {"0x80","INT 80h — Linux ABI in Wine; also used as alternative syscall in shellcode"}
        };
        // Enumerate hooked by scanning kernel module boundaries
        struct IDTR { WORD limit; ULONG_PTR base; } __attribute__((packed));
        IDTR idtr = {};
        __sidt(&idtr);
        result["hooked_vectors"] = json::array();
        result["idtr_accessible"] = (idtr.base != 0);
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
