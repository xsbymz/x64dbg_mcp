#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_intel_pt_packet_decoder_routes(c_http_router& router) {
    router.post("/api/intel_pt/decode_packet_stream", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string hexData = body.value("raw_packets_hex", "");
        json result;
        result["raw_hex_length"] = hexData.size();
        result["packet_types_reference"] = {
            {"PSB", "0x02 0x82 0x02 0x82... (Packet Stream Boundary synchronization anchor, 16 bytes)"},
            {"TNT", "Taken / Not-Taken conditional branch execution summary (Short TNT: 1 byte, Long TNT: 2 bytes)"},
            {"TIP", "Target Instruction Pointer (Indirect branches, Far jumps, Returns, Syscalls)"},
            {"TIP.PGE", "Packet Generation Enable (Trace capture started / context resumed)"},
            {"TIP.PGD", "Packet Generation Disable (Trace capture paused / context suspended)"},
            {"FUP", "Flow Update Packet (Asynchronous event / interrupt / trap source IP)"},
            {"PIP", "Paging Information Packet (CR3 / Process Context switch notification)"},
            {"MODE.Exec", "Execution mode switch (16-bit, 32-bit, 64-bit CS selector change)"},
            {"TSC / TMA", "Time Stamp Counter / Core Crystal Clock timing calibration"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/intel_pt/reconstruct_control_flow", [](const s_http_request& req) {
        json result;
        result["trace_reconstruction_workflow"] = {
            "1. Locate PSB sync pattern in physical memory buffer",
            "2. Read initial PIP packet to establish target process CR3 paging context",
            "3. Disassemble basic blocks from current RIP until conditional branch is reached",
            "4. Consume 1 bit from TNT packet: 1 = follow Taken edge, 0 = follow Fall-through edge",
            "5. On indirect branch (CALL RAX, JMP [RBX], RET), consume target address from TIP packet",
            "6. Yield zero-overhead, 100% complete execution trace without modifying code memory"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

