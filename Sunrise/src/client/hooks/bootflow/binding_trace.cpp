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
 * DIAGNOSTIC sense_update consumer finder. FUN_004c74b0 is the generic schema deserializer thunk; its
 * first argument is the class id being parsed. When the client receives a server->client sense_update
 * (message type 6) with a non-empty delta, it deserializes that delta with class 0x80808769. Detour
 * the thunk, and when the class is 0x80808769 log the return address as an image RVA -- that caller is
 * the sense_update handler / consumer, which static analysis cannot reach because the deserializer is
 * invoked only indirectly. Only rcx and the return address are read, never memory, so nothing faults.
 * Pair with command_emit (a non-empty command) to make the client take this path. To be removed.
 */
constexpr std::string_view kDeserText =
    "48 83 EC 38 8B 44 24 60 89 44 24 20 E8 ? ? ? ? B0 01 48 83 C4 38 C3";
/** Compiled pattern bytes of the signature text above. */
constexpr auto kDeser = signature<signature_length(kDeserText)>(kDeserText);

/** RVA of the traced thunk, used to recover the image base from the resolved target. */
constexpr std::uintptr_t kDeserRva = 0x4c74b0;
/** The sense_update delta schema class id. */
constexpr std::uintptr_t kSenseClass = 0x80808769;
/** Distinct caller sites to log before the trace goes quiet. */
constexpr std::size_t kSeenCap = 24;

hooking::detour::Handle g_handle{};
std::uintptr_t g_base{};
std::array<std::atomic<std::uint32_t>, kSeenCap> g_seen{};

using Original = char(__fastcall*)(void*, void*, void*, void*, void*);

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
                line.data(), line.size(), "ev=senseconsumer stage=deser caller_rva=0x%08X", rva);
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

/** Records the caller RVA when the sense schema is deserialized, then forwards unchanged. */
__declspec(noinline) char __fastcall deserialize(void* rcx,
                                                 void* rdx,
                                                 void* r8,
                                                 void* r9,
                                                 void* stack5) noexcept {
    if (reinterpret_cast<std::uintptr_t>(rcx) == kSenseClass && g_base != 0) {
        const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
        if (caller > g_base) {
            report_caller(static_cast<std::uint32_t>(caller - g_base));
        }
    }
    return reinterpret_cast<Original>(g_handle.original)(rcx, rdx, r8, r9, stack5);
}

} // namespace

/**
 * Attaches the sense_update consumer finder.
 * @return True when the target is found and the detour attaches.
 */
bool install_binding_trace() noexcept {
    if (g_handle.attached) {
        return true;
    }
    std::byte* const target = scan_main_image_unique(kDeser, "sense_deserializer");
    if (target == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=senseconsumer result=fail reason=target");
        return false;
    }
    g_base = reinterpret_cast<std::uintptr_t>(target) - kDeserRva;
    const hooking::detour::Spec spec{target, reinterpret_cast<void*>(&deserialize)};
    if (!hooking::detour::install(spec, g_handle)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=senseconsumer result=fail reason=attach");
        return false;
    }
    core::log::write(
        core::log::Channel::client, core::log::Level::info, "ev=senseconsumer result=ok");
    return true;
}

/** Detaches the sense_update consumer finder. */
void uninstall_binding_trace() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
}

} // namespace sunrise::client::hooks::bootflow
