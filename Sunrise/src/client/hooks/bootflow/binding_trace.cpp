#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <intrin.h>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../hooking/detour.h"
#include "internal.h"

namespace sunrise::client::hooks::bootflow {
namespace {

/**
 * DIAGNOSTIC binding-creation trace. FUN_00c22dd0 (RVA 0xc22dd0) is the binding-manager callback the
 * content system invokes; it walks the loaded-object table and calls the binding creator FUN_01703690
 * (which sets object+0x18, the flag the seed machine reads). It is called only indirectly through a
 * runtime callback, so static analysis cannot reach its caller -- the content-load trigger. Hook it
 * and log its return address, resolved to an image RVA, once per distinct site. That RVA is the
 * content-load trigger, the step the deleted mission director would drive to make a squad load. The
 * original is always called, so the game keeps loading content normally. To be removed.
 */
constexpr std::string_view kBindingTraceText =
    "48 83 EC 28 E8 ? ? ? ? 48 85 C0 74 ? 48 89 5C 24 20 E8 ? ? ? ? 48 8B D8 E8";
/** Compiled pattern bytes of the signature text above. */
constexpr auto kBindingTrace = signature<signature_length(kBindingTraceText)>(kBindingTraceText);

/** RVA of the traced function, used to recover the image base from the resolved target. */
constexpr std::uintptr_t kBindingTraceRva = 0xc22dd0;

/** Distinct caller sites to log before the trace goes quiet. */
constexpr std::size_t kSeenCap = 24;

hooking::detour::Handle g_handle{};
std::uintptr_t g_base{};
std::array<std::atomic<std::uint32_t>, kSeenCap> g_seen{};

using Original = void(__fastcall*)(void*, void*, void*, void*);

/** Logs one caller RVA the first time it is seen, ignoring repeats and losing races safely. */
void report_caller(std::uint32_t rva) noexcept {
    std::size_t slot = 0;
    while (slot < kSeenCap) {
        const std::uint32_t seen = g_seen[slot].load(std::memory_order_relaxed);
        if (seen == rva) {
            return;
        }
        if (seen == 0) {
            std::uint32_t expected = 0;
            if (!g_seen[slot].compare_exchange_strong(expected, rva, std::memory_order_relaxed)) {
                continue;
            }
            std::array<char, 96> line{};
            const int written = std::snprintf(
                line.data(), line.size(), "ev=bindtrace stage=content_load caller_rva=0x%08X", rva);
            if (written > 0) {
                core::log::write(core::log::Channel::client,
                                 core::log::Level::info,
                                 {line.data(), static_cast<std::size_t>(written)});
            }
            return;
        }
        ++slot;
    }
}

/** Records the caller RVA, then forwards to the native binding manager unchanged. */
__declspec(noinline) void __fastcall binding_manager(void* a, void* b, void* c, void* d) noexcept {
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    if (g_base != 0 && caller > g_base) {
        report_caller(static_cast<std::uint32_t>(caller - g_base));
    }
    reinterpret_cast<Original>(g_handle.original)(a, b, c, d);
}

} // namespace

/**
 * Attaches the binding-creation trace.
 * @return True when the target is found and the detour attaches.
 */
bool install_binding_trace() noexcept {
    if (g_handle.attached) {
        return true;
    }
    std::byte* const target = scan_main_image_unique(kBindingTrace, "binding_trace");
    if (target == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bindtrace result=fail reason=target");
        return false;
    }
    g_base = reinterpret_cast<std::uintptr_t>(target) - kBindingTraceRva;
    const hooking::detour::Spec spec{target, reinterpret_cast<void*>(&binding_manager)};
    if (!hooking::detour::install(spec, g_handle)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bindtrace result=fail reason=attach");
        return false;
    }
    core::log::write(
        core::log::Channel::client, core::log::Level::info, "ev=bindtrace result=ok");
    return true;
}

/** Detaches the binding-creation trace. */
void uninstall_binding_trace() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
}

} // namespace sunrise::client::hooks::bootflow
