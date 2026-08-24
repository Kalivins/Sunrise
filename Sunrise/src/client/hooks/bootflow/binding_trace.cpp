#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../hooking/detour.h"
#include "internal.h"

namespace sunrise::client::hooks::bootflow {
namespace {

/**
 * DIAGNOSTIC binding-creation ground-truth trace. FUN_01703690 (RVA 0x1703690) is the binding
 * creator: it attaches a content object (its 4th argument) to a placed object (its 4th-argument
 * receiver) and sets receiver+0x18, the flag the seed machine reads. Hooking it captures the two
 * pointers at the source, so their structure is read from live memory instead of guessed from
 * static offsets. Log, once per distinct receiver, the receiver's leading bytes (to locate its
 * registry key against the known participant keys) and the content pointer, then forward unchanged.
 * This maps what actually loads and binds during a mission, which is where a squad's content would
 * have to appear. To be removed.
 */
constexpr std::string_view kCreatorText =
    "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B F1 49 8B D8 48 81 C1 70 02 00 00 48 8B FA";
/** Compiled pattern bytes of the signature text above. */
constexpr auto kCreator = signature<signature_length(kCreatorText)>(kCreatorText);

/** Distinct receiver objects to report before the trace goes quiet. */
constexpr std::size_t kSeenCap = 12;

hooking::detour::Handle g_handle{};
std::array<std::atomic<std::uintptr_t>, kSeenCap> g_seen{};

using Original = void(__fastcall*)(void*, void*, void*, void*, void*);

/** @return True if the receiver pointer is new and was claimed, false if seen or the table is full. */
[[nodiscard]] bool claim(std::uintptr_t key) noexcept {
    std::size_t slot = 0;
    while (slot < kSeenCap) {
        const std::uintptr_t seen = g_seen[slot].load(std::memory_order_relaxed);
        if (seen == key) {
            return false;
        }
        if (seen == 0) {
            std::uintptr_t expected = 0;
            if (g_seen[slot].compare_exchange_strong(expected, key, std::memory_order_relaxed)) {
                return true;
            }
            continue;
        }
        ++slot;
    }
    return false;
}

/** Dumps the receiver and content pointers, then forwards to the native binding creator. */
__declspec(noinline) void __fastcall creator(void* rcx, void* rdx, void* r8, void* r9, void* stack5) noexcept {
    // Log only the pointers -- never dereference the receiver. During load this hook fires with a
    // not-yet-constructed object, so reading its bytes faults and freezes the client; the sweep only
    // needs to know that a bind (a content load) happened, which the pointers alone report.
    void* const receiver = r9;
    void* const content = r8;
    if (receiver != nullptr && claim(reinterpret_cast<std::uintptr_t>(receiver))) {
        std::array<char, 96> line{};
        const int written = std::snprintf(
            line.data(),
            line.size(),
            "ev=bindtrace stage=bind obj=0x%llX content=0x%llX",
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(receiver)),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(content)));
        if (written > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
    reinterpret_cast<Original>(g_handle.original)(rcx, rdx, r8, r9, stack5);
}

} // namespace

/**
 * Attaches the binding-creation ground-truth trace.
 * @return True when the target is found and the detour attaches.
 */
bool install_binding_trace() noexcept {
    if (g_handle.attached) {
        return true;
    }
    std::byte* const target = scan_main_image_unique(kCreator, "binding_creator");
    if (target == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bindtrace result=fail reason=target");
        return false;
    }
    const hooking::detour::Spec spec{target, reinterpret_cast<void*>(&creator)};
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

/** Detaches the binding-creation ground-truth trace. */
void uninstall_binding_trace() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
}

} // namespace sunrise::client::hooks::bootflow
