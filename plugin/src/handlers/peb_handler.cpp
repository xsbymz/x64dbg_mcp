#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>

namespace handlers {

static nlohmann::json read_peb_ldr(duint pid, duint peb_addr) {
    auto& bridge = get_bridge();
    nlohmann::json result;

    duint ldr_offset = 0x18;
    duint ldr_addr = 0;
    auto ldr_data = bridge.read_memory(peb_addr + ldr_offset, sizeof(duint));
    if (ldr_data.has_value() && ldr_data->size() >= sizeof(duint)) {
        std::memcpy(&ldr_addr, ldr_data->data(), sizeof(duint));
    }
    if (ldr_addr == 0) return result;

    auto lists = nlohmann::json::object();
    const char* list_names[] = {"in_load_order", "in_memory_order", "in_init_order"};
    duint list_offsets[] = {0x10, 0x20, 0x30};

    for (int i = 0; i < 3; ++i) {
        nlohmann::json entries = nlohmann::json::array();
        duint list_head = 0;
        auto list_data = bridge.read_memory(ldr_addr + list_offsets[i], sizeof(duint));
        if (list_data.has_value() && list_data->size() >= sizeof(duint)) {
            std::memcpy(&list_head, list_data->data(), sizeof(duint));
        }
        if (list_head == 0) {
            lists[list_names[i]] = entries;
            continue;
        }

        duint flink = list_head;
        duint blink = 0;
        for (int iter = 0; iter < 256 && flink != list_head && flink != 0; ++iter) {
            auto entry_data = bridge.read_memory(flink, sizeof(duint) * 4);
            if (!entry_data.has_value() || entry_data->size() < sizeof(duint) * 4) break;

            duint base = 0;
            duint size = 0;
            duint name_addr = 0;
            duint flags = 0;
            std::memcpy(&base, entry_data->data(), sizeof(duint));
            std::memcpy(&size, entry_data->data() + sizeof(duint), sizeof(duint));
            std::memcpy(&name_addr, entry_data->data() + sizeof(duint) * 2, sizeof(duint));
            std::memcpy(&flags, entry_data->data() + sizeof(duint) * 3, sizeof(duint));

            std::string path;
            if (name_addr != 0) {
                auto name_data = bridge.read_memory(name_addr, 260);
                if (name_data.has_value()) {
                    path = std::string(reinterpret_cast<const char*>(name_data->data()));
                    auto null_pos = path.find('\0');
                    if (null_pos != std::string::npos) path.resize(null_pos);
                }
            }

            entries.push_back({
                {"base",  format_utils::format_address(base)},
                {"size",  size},
                {"path",  path},
                {"flags", format_utils::format_address(flags)},
                {"name",  bridge.get_module_at(base)}
            });

            flink = blink;
            auto next_data = bridge.read_memory(flink, sizeof(duint) * 2);
            if (!next_data.has_value() || next_data->size() < sizeof(duint) * 2) break;
            std::memcpy(&flink, next_data->data(), sizeof(duint));
            std::memcpy(&blink, next_data->data() + sizeof(duint), sizeof(duint));
        }
        lists[list_names[i]] = entries;
    }

    return lists;
}

void register_peb_routes(c_http_router& router) {
    router.get("/api/peb/full", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid_str = req.get_query("pid", "");
        DWORD pid = 0;
        if (pid_str.empty()) {
            pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        } else {
            pid = static_cast<DWORD>(std::stoul(pid_str));
        }

        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::not_found("Failed to get PEB address");
        }

        nlohmann::json data = {
            {"peb_address", format_utils::format_address(peb_addr)},
            {"pid",         pid}
        };

        auto being_debugged = bridge.read_memory(peb_addr + 0x2, 1);
        if (being_debugged.has_value() && !being_debugged->empty()) {
            data["being_debugged"] = static_cast<int>(being_debugged->at(0));
        }

#ifdef _WIN64
        constexpr duint ntglobalflag_offset = 0xBC;
        constexpr duint heap_offset = 0x30;
        constexpr duint image_base_offset = 0x10;
        constexpr duint process_parameters_offset = 0x20;
        constexpr duint activation_context_offset = 0x38;
        constexpr duint token_offset = 0x48;
#else
        constexpr duint ntglobalflag_offset = 0x68;
        constexpr duint heap_offset = 0x18;
        constexpr duint image_base_offset = 0x08;
        constexpr duint process_parameters_offset = 0x10;
        constexpr duint activation_context_offset = 0x1C;
        constexpr duint token_offset = 0xE4;
#endif

        auto nt_global = bridge.read_memory(peb_addr + ntglobalflag_offset, 4);
        if (nt_global.has_value() && nt_global->size() >= 4) {
            DWORD flags = 0;
            std::memcpy(&flags, nt_global->data(), 4);
            data["nt_global_flag"] = format_utils::format_address(flags);
            data["nt_global_flag_decimal"] = flags;
        }

        auto heap_data = bridge.read_memory(peb_addr + heap_offset, sizeof(duint));
        if (heap_data.has_value() && heap_data->size() >= sizeof(duint)) {
            duint heap_addr = 0;
            std::memcpy(&heap_addr, heap_data->data(), sizeof(duint));
            data["process_heap"] = format_utils::format_address(heap_addr);
        }

        auto img_base_data = bridge.read_memory(peb_addr + image_base_offset, sizeof(duint));
        if (img_base_data.has_value() && img_base_data->size() >= sizeof(duint)) {
            duint img_base = 0;
            std::memcpy(&img_base, img_base_data->data(), sizeof(duint));
            data["image_base_address"] = format_utils::format_address(img_base);
        }

        data["ldr"] = read_peb_ldr(pid, peb_addr);

        auto rtl_data = bridge.read_memory(peb_addr + process_parameters_offset, sizeof(duint));
        if (rtl_data.has_value() && rtl_data->size() >= sizeof(duint)) {
            duint rtl_addr = 0;
            std::memcpy(&rtl_addr, rtl_data->data(), sizeof(duint));
            if (rtl_addr != 0) {
                nlohmann::json params;
                params["process_parameters_address"] = format_utils::format_address(rtl_addr);

                auto cmdline_data = bridge.read_memory(rtl_addr + 0x40, sizeof(duint));
                if (cmdline_data.has_value() && cmdline_data->size() >= sizeof(duint)) {
                    duint cmdline_addr = 0;
                    std::memcpy(&cmdline_addr, cmdline_data->data(), sizeof(duint));
                    USHORT cmdline_len = 0;
                    auto len_data = bridge.read_memory(rtl_addr + 0x48, sizeof(USHORT));
                    if (len_data.has_value() && len_data->size() >= sizeof(USHORT)) {
                        std::memcpy(&cmdline_len, len_data->data(), sizeof(USHORT));
                    }
                    if (cmdline_addr != 0 && cmdline_len > 0) {
                        auto cmdline_bytes = bridge.read_memory(cmdline_addr, cmdline_len);
                        if (cmdline_bytes.has_value()) {
                            std::string cmdline(reinterpret_cast<const char*>(cmdline_bytes->data()), cmdline_len);
                            params["command_line"] = cmdline;
                        }
                    }
                }

                auto img_path_data = bridge.read_memory(rtl_addr + 0x60, sizeof(duint));
                if (img_path_data.has_value() && img_path_data->size() >= sizeof(duint)) {
                    duint img_path_addr = 0;
                    std::memcpy(&img_path_addr, img_path_data->data(), sizeof(duint));
                    USHORT path_len = 0;
                    auto path_len_data = bridge.read_memory(rtl_addr + 0x68, sizeof(USHORT));
                    if (path_len_data.has_value() && path_len_data->size() >= sizeof(USHORT)) {
                        std::memcpy(&path_len, path_len_data->data(), sizeof(USHORT));
                    }
                    if (img_path_addr != 0 && path_len > 0) {
                        auto path_bytes = bridge.read_memory(img_path_addr, path_len);
                        if (path_bytes.has_value()) {
                            std::string img_path(reinterpret_cast<const char*>(path_bytes->data()), path_len);
                            params["image_path_name"] = img_path;
                        }
                    }
                }

                auto dll_path_data = bridge.read_memory(rtl_addr + 0x70, sizeof(duint));
                if (dll_path_data.has_value() && dll_path_data->size() >= sizeof(duint)) {
                    duint dll_path_addr = 0;
                    std::memcpy(&dll_path_addr, dll_path_data->data(), sizeof(duint));
                    params["dll_path"] = format_utils::format_address(dll_path_addr);
                }

                auto win_title_data = bridge.read_memory(rtl_addr + 0x80, sizeof(duint));
                if (win_title_data.has_value() && win_title_data->size() >= sizeof(duint)) {
                    duint win_title_addr = 0;
                    std::memcpy(&win_title_addr, win_title_data->data(), sizeof(duint));
                    params["window_title"] = format_utils::format_address(win_title_addr);
                }

                auto desktop_data = bridge.read_memory(rtl_addr + 0x90, sizeof(duint));
                if (desktop_data.has_value() && desktop_data->size() >= sizeof(duint)) {
                    duint desktop_addr = 0;
                    std::memcpy(&desktop_addr, desktop_data->data(), sizeof(duint));
                    params["desktop"] = format_utils::format_address(desktop_addr);
                }

                auto env_data = bridge.read_memory(rtl_addr + 0x80, sizeof(duint));
                if (env_data.has_value() && env_data->size() >= sizeof(duint)) {
                    duint env_addr = 0;
                    std::memcpy(&env_addr, env_data->data(), sizeof(duint));
                    params["environment_pointer"] = format_utils::format_address(env_addr);
                }

                data["process_parameters"] = params;
            }
        }

        auto act_data = bridge.read_memory(peb_addr + activation_context_offset, sizeof(duint));
        if (act_data.has_value() && act_data->size() >= sizeof(duint)) {
            duint act_addr = 0;
            std::memcpy(&act_addr, act_data->data(), sizeof(duint));
            data["activation_context_data"] = format_utils::format_address(act_addr);
        }

        auto tok_data = bridge.read_memory(peb_addr + token_offset, sizeof(duint));
        if (tok_data.has_value() && tok_data->size() >= sizeof(duint)) {
            duint tok_addr = 0;
            std::memcpy(&tok_addr, tok_data->data(), sizeof(duint));
            data["token_address"] = format_utils::format_address(tok_addr);
        }

        return s_http_response::ok(data);
    });

    router.get("/api/peb/ldr", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid_str = req.get_query("pid", "");
        DWORD pid = 0;
        if (pid_str.empty()) {
            pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        } else {
            pid = static_cast<DWORD>(std::stoul(pid_str));
        }

        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::not_found("Failed to get PEB address");
        }

        auto ldr_data = read_peb_ldr(pid, peb_addr);
        return s_http_response::ok({
            {"peb_address", format_utils::format_address(peb_addr)},
            {"pid",         pid},
            {"ldr",         ldr_data}
        });
    });

    router.get("/api/peb/cmdline", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid_str = req.get_query("pid", "");
        DWORD pid = 0;
        if (pid_str.empty()) {
            pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        } else {
            pid = static_cast<DWORD>(std::stoul(pid_str));
        }

        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::not_found("Failed to get PEB address");
        }

#ifdef _WIN64
        constexpr duint process_parameters_offset = 0x20;
#else
        constexpr duint process_parameters_offset = 0x10;
#endif

        auto rtl_data = bridge.read_memory(peb_addr + process_parameters_offset, sizeof(duint));
        if (!rtl_data.has_value() || rtl_data->size() < sizeof(duint)) {
            return s_http_response::internal_error("Failed to read RTL_USER_PROCESS_PARAMETERS pointer");
        }

        duint rtl_addr = 0;
        std::memcpy(&rtl_addr, rtl_data->data(), sizeof(duint));
        if (rtl_addr == 0) {
            return s_http_response::internal_error("RTL_USER_PROCESS_PARAMETERS is null");
        }

        USHORT cmdline_len = 0;
        auto len_data = bridge.read_memory(rtl_addr + 0x48, sizeof(USHORT));
        if (len_data.has_value() && len_data->size() >= sizeof(USHORT)) {
            std::memcpy(&cmdline_len, len_data->data(), sizeof(USHORT));
        }

        auto cmdline_ptr_data = bridge.read_memory(rtl_addr + 0x40, sizeof(duint));
        if (!cmdline_ptr_data.has_value() || cmdline_ptr_data->size() < sizeof(duint)) {
            return s_http_response::internal_error("Failed to read command line pointer");
        }

        duint cmdline_addr = 0;
        std::memcpy(&cmdline_addr, cmdline_ptr_data->data(), sizeof(duint));
        if (cmdline_addr == 0 || cmdline_len == 0) {
            return s_http_response::ok({
                {"cmdline", ""},
                {"length",  0}
            });
        }

        auto cmdline_bytes = bridge.read_memory(cmdline_addr, cmdline_len);
        if (!cmdline_bytes.has_value()) {
            return s_http_response::internal_error("Failed to read command line");
        }

        std::string cmdline(reinterpret_cast<const char*>(cmdline_bytes->data()), cmdline_len);
        return s_http_response::ok({
            {"cmdline", cmdline},
            {"length",  cmdline_len}
        });
    });

    router.get("/api/peb/env", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid_str = req.get_query("pid", "");
        DWORD pid = 0;
        if (pid_str.empty()) {
            pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        } else {
            pid = static_cast<DWORD>(std::stoul(pid_str));
        }

        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::not_found("Failed to get PEB address");
        }

#ifdef _WIN64
        constexpr duint process_parameters_offset = 0x20;
#else
        constexpr duint process_parameters_offset = 0x10;
#endif

        auto rtl_data = bridge.read_memory(peb_addr + process_parameters_offset, sizeof(duint));
        if (!rtl_data.has_value() || rtl_data->size() < sizeof(duint)) {
            return s_http_response::internal_error("Failed to read RTL_USER_PROCESS_PARAMETERS pointer");
        }

        duint rtl_addr = 0;
        std::memcpy(&rtl_addr, rtl_data->data(), sizeof(duint));
        if (rtl_addr == 0) {
            return s_http_response::internal_error("RTL_USER_PROCESS_PARAMETERS is null");
        }

        duint env_addr = 0;
        auto env_data = bridge.read_memory(rtl_addr + 0x80, sizeof(duint));
        if (env_data.has_value() && env_data->size() >= sizeof(duint)) {
            std::memcpy(&env_addr, env_data->data(), sizeof(duint));
        }

        if (env_addr == 0) {
            return s_http_response::ok({
                {"environment_block_address", "0x0"},
                {"count", 0},
                {"variables", nlohmann::json::array()}
            });
        }

        constexpr size_t kMaxEnvSize = 4096;
        auto env_bytes = bridge.read_memory(env_addr, kMaxEnvSize);
        if (!env_bytes.has_value()) {
            return s_http_response::internal_error("Failed to read environment block");
        }

        std::string env_block(reinterpret_cast<const char*>(env_bytes->data()), env_bytes->size());
        auto vars = nlohmann::json::array();
        size_t pos = 0;
        while (pos < env_block.size() && vars.size() < 512) {
            size_t end = env_block.find('\0', pos);
            if (end == std::string::npos) break;
            std::string entry = env_block.substr(pos, end - pos);
            if (entry.empty()) break;
            vars.push_back(entry);
            pos = end + 1;
        }

        return s_http_response::ok({
            {"environment_block_address", format_utils::format_address(env_addr)},
            {"count",     vars.size()},
            {"variables", vars}
        });
    });

    router.get("/api/teb/full", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto tid_str = req.get_query("tid", "");
        DWORD tid = 0;
        if (tid_str.empty()) {
            tid = static_cast<DWORD>(bridge.eval_expression("$tid"));
        } else {
            tid = static_cast<DWORD>(std::stoul(tid_str));
        }

        auto teb_addr = DbgGetTebAddress(tid);
        if (teb_addr == 0) {
            return s_http_response::not_found("Failed to get TEB address");
        }

        nlohmann::json data = {
            {"teb_address", format_utils::format_address(teb_addr)},
            {"tid",         tid}
        };

        auto seh_data = bridge.read_memory(teb_addr, sizeof(duint));
        if (seh_data.has_value() && seh_data->size() >= sizeof(duint)) {
            duint seh = 0;
            std::memcpy(&seh, seh_data->data(), sizeof(duint));
            data["seh_frame"] = format_utils::format_address(seh);
        }

#ifdef _WIN64
        constexpr duint stack_base_offset = 0x8;
        constexpr duint stack_limit_offset = 0x10;
        constexpr duint stack_commit_offset = 0x18;
        constexpr duint stack_reserved_offset = 0x20;
        constexpr duint peb_offset = 0x60;
        constexpr duint tls_pointer_offset = 0x58;
        constexpr duint last_error_offset = 0x68;
#else
        constexpr duint stack_base_offset = 0x4;
        constexpr duint stack_limit_offset = 0x8;
        constexpr duint stack_commit_offset = 0xC;
        constexpr duint stack_reserved_offset = 0x10;
        constexpr duint peb_offset = 0x30;
        constexpr duint tls_pointer_offset = 0x2C;
        constexpr duint last_error_offset = 0x34;
#endif

        auto stack_base = bridge.read_memory(teb_addr + stack_base_offset, sizeof(duint));
        if (stack_base.has_value() && stack_base->size() >= sizeof(duint)) {
            duint val = 0;
            std::memcpy(&val, stack_base->data(), sizeof(duint));
            data["stack_base"] = format_utils::format_address(val);
        }

        auto stack_limit = bridge.read_memory(teb_addr + stack_limit_offset, sizeof(duint));
        if (stack_limit.has_value() && stack_limit->size() >= sizeof(duint)) {
            duint val = 0;
            std::memcpy(&val, stack_limit->data(), sizeof(duint));
            data["stack_limit"] = format_utils::format_address(val);
        }

        auto stack_commit = bridge.read_memory(teb_addr + stack_commit_offset, sizeof(duint));
        if (stack_commit.has_value() && stack_commit->size() >= sizeof(duint)) {
            duint val = 0;
            std::memcpy(&val, stack_commit->data(), sizeof(duint));
            data["stack_commit"] = format_utils::format_address(val);
        }

        auto stack_reserved = bridge.read_memory(teb_addr + stack_reserved_offset, sizeof(duint));
        if (stack_reserved.has_value() && stack_reserved->size() >= sizeof(duint)) {
            duint val = 0;
            std::memcpy(&val, stack_reserved->data(), sizeof(duint));
            data["stack_reserved"] = format_utils::format_address(val);
        }

        auto peb = bridge.read_memory(teb_addr + peb_offset, sizeof(duint));
        if (peb.has_value() && peb->size() >= sizeof(duint)) {
            duint val = 0;
            std::memcpy(&val, peb->data(), sizeof(duint));
            data["peb_address"] = format_utils::format_address(val);
        }

        auto tls_ptr = bridge.read_memory(teb_addr + tls_pointer_offset, sizeof(duint));
        if (tls_ptr.has_value() && tls_ptr->size() >= sizeof(duint)) {
            duint val = 0;
            std::memcpy(&val, tls_ptr->data(), sizeof(duint));
            data["thread_local_storage_pointer"] = format_utils::format_address(val);
        }

        auto last_err = bridge.read_memory(teb_addr + last_error_offset, sizeof(DWORD));
        if (last_err.has_value() && last_err->size() >= sizeof(DWORD)) {
            DWORD err = 0;
            std::memcpy(&err, last_err->data(), sizeof(DWORD));
            data["last_error"] = format_utils::format_address(err);
        }

        data["thread_id"] = tid;
        data["process_id"] = static_cast<DWORD>(bridge.eval_expression("$pid"));

        return s_http_response::ok(data);
    });
}

} // namespace handlers
