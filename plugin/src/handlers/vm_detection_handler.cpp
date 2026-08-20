#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <algorithm>
#include <regex>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) out.push_back(item);
    return out;
}

static std::vector<std::pair<duint, std::string>> scan_strings_in_memory(
    c_bridge_executor& bridge, duint start, size_t size, bool wide = false)
{
    std::vector<std::pair<duint, std::string>> found;
    auto mem = bridge.read_memory(start, size);
    if (!mem.has_value() || mem->size() < 4) return found;

    std::string current;
    size_t min_len = 4;
    for (size_t i = 0; i < mem->size(); ++i) {
        uint8_t b = (*mem)[i];
        if (b >= 0x20 && b < 0x7F) {
            current += static_cast<char>(b);
        } else {
            if (current.size() >= min_len) {
                found.emplace_back(start + static_cast<duint>(i - current.size()), current);
            }
            current.clear();
        }
    }
    if (current.size() >= min_len) {
        found.emplace_back(start + static_cast<duint>(mem->size() - current.size()), current);
    }
    return found;
}

void register_vm_detection_routes(c_http_router& router) {
    router.get("/api/vm/detect", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto artifacts = nlohmann::json::array();
        int score = 0;
        std::string vm_type = "none";

        auto regs = bridge.get_register_dump();
        if (regs.has_value()) {
            const auto& r = regs.value();
            if (r.regcontext.cax != 0 || r.regcontext.cbx != 0) {
                artifacts.push_back({
                    {"type", "cpuid"},
                    {"address", "cpuid_leaf_0x40000000"},
                    {"description", "Non-zero hypervisor signature in CPUID"}
                });
                score += 30;
            }
        }

        std::vector<std::pair<std::string, std::string>> vm_strings = {
            {"VBox", "VirtualBox"},
            {"VMware", "VMware"},
            {"QEMU", "QEMU"},
            {"Parallels", "Parallels"},
            {"Hypervisor", "Generic Hypervisor"}
        };

        auto mods = bridge.get_memory_map();
        if (mods.has_value()) {
            for (const auto& page : mods.value()) {
                if (!page.contains("info") || !page["info"].is_string()) continue;
                std::string info = page["info"];
                for (const auto& [needle, vm] : vm_strings) {
                    if (info.find(needle) != std::string::npos) {
                        artifacts.push_back({
                            {"type", "module"},
                            {"address", page["base"]},
                            {"description", "VM-related module: " + info},
                            {"vm_type", vm}
                        });
                        score += 40;
                        vm_type = vm;
                    }
                }
            }
        }

        std::string confidence = "none";
        if (score >= 70) confidence = "high";
        else if (score >= 40) confidence = "medium";
        else if (score >= 10) confidence = "low";

        return s_http_response::ok({
            {"is_vm", score >= 40},
            {"confidence", confidence},
            {"vm_type", vm_type},
            {"score", score},
            {"artifacts", artifacts}
        });
    });

    router.get("/api/vm/registry_artifacts", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto artifacts = nlohmann::json::array();
        std::vector<std::pair<std::string, std::string>> checks = {
            {"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT", "VBOX__"},
            {"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT", "VBOX__"},
            {"HKEY_LOCAL_MACHINE\\SOFTWARE\\Oracle", "VirtualBox"},
            {"HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware", "VMware"},
            {"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "VMware Tools"}
        };

        for (const auto& [key, needle] : checks) {
            auto val = bridge.eval_expression("reg(\"" + key + "\")");
            if (val != 0) {
                std::string vm_type = key.find("VBOX") != std::string::npos ? "VirtualBox" : "VMware";
                artifacts.push_back({
                    {"key", key},
                    {"value", format_utils::format_address(val)},
                    {"vm_type", vm_type}
                });
            }
        }

        return s_http_response::ok({
            {"artifacts", artifacts},
            {"count", artifacts.size()}
        });
    });

    router.get("/api/vm/driver_check", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto drivers = nlohmann::json::array();
        std::vector<std::pair<std::string, std::string>> vm_drivers = {
            {"VBoxGuest.sys", "VirtualBox"},
            {"VBoxMouse.sys", "VirtualBox"},
            {"VBoxAudio.sys", "VirtualBox"},
            {"VBoxSF.sys", "VirtualBox"},
            {"VBoxVideo.sys", "VirtualBox"},
            {"vmwgfx.sys", "VMware"},
            {"vmx86.sys", "VMware"},
            {"vmnet.sys", "VMware"}
        };

        auto mods = bridge.get_memory_map();
        if (mods.has_value()) {
            for (const auto& page : mods.value()) {
                if (!page.contains("info") || !page["info"].is_string()) continue;
                std::string info = page["info"];
                for (const auto& [driver, vm] : vm_drivers) {
                    if (info.find(driver) != std::string::npos) {
                        drivers.push_back({
                            {"name", driver},
                            {"path", info},
                            {"vm_type", vm}
                        });
                    }
                }
            }
        }

        return s_http_response::ok({
            {"drivers", drivers},
            {"count", drivers.size()}
        });
    });

    router.get("/api/vm/cpuid_check", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto regs = bridge.get_register_dump();
        bool hypervisor_present = false;
        std::string vendor = "unknown";
        uint32_t leaf_high = 0, leaf_low = 0;

        if (regs.has_value()) {
            const auto& r = regs.value();
            hypervisor_present = (r.regcontext.cax != 0 || r.regcontext.cbx != 0);
            leaf_high = static_cast<uint32_t>(r.regcontext.cax >> 32);
            leaf_low = static_cast<uint32_t>(r.regcontext.cax);
            vendor = format_utils::format_address(r.regcontext.cbx) + format_utils::format_address(r.regcontext.ccx) + format_utils::format_address(r.regcontext.cdx);
        }

        return s_http_response::ok({
            {"hypervisor_present", hypervisor_present},
            {"vendor", vendor},
            {"leaf_0x40000000_high", format_utils::format_address(leaf_high)},
            {"leaf_0x40000000_low", format_utils::format_address(leaf_low)}
        });
    });
}

} // namespace handlers
