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
 * DIAGNOSTIC finders for the server->client sense_update (message type 6) consumer. The activity
 * message dispatch is rebuilt at runtime, so the type-6 handler has no static caller and cannot be
 * reached by disassembly alone. Two detours recover it live, each reading only a register or the
 * return address (never memory), so nothing faults during mission load:
 *
 *   1. Deserializer trace. FUN_004c74b0 is the generic schema deserializer thunk; its first argument
 *      is the class id. When the class is the sense delta schema 0x80808769 the caller is the type-6
 *      handler, logged as an image RVA. Fires only if the client parses a received delta through the
 *      generic deserializer (pair with a non-empty command emit).
 *   2. Dispatcher trace. The roster decoder 0x3c9fc0 is entered by a jmp tail-call from the activity
 *      dispatch stub, so its return address is the dispatcher site that routes activity messages by
 *      type. The roster is decoded at mission load with no command needed, so this always yields the
 *      dispatcher, whose type-6 branch is the sense handler.
 *
 * Both are removed once the consumer is identified.
 */
constexpr std::string_view kDeserText =
    "48 83 EC 38 8B 44 24 60 89 44 24 20 E8 ? ? ? ? B0 01 48 83 C4 38 C3";
constexpr auto kDeser = signature<signature_length(kDeserText)>(kDeserText);
constexpr std::uintptr_t kDeserRva = 0x4c74b0;
constexpr std::uintptr_t kSenseClass = 0x80808769;

constexpr std::string_view kRosterText =
    "40 55 53 56 41 55 48 8D AC 24 48 FD FF FF 48 81 EC B8 03 00 00";
constexpr auto kRoster = signature<signature_length(kRosterText)>(kRosterText);
constexpr std::uintptr_t kRosterRva = 0x3c9fc0;

/** Distinct caller sites to log per trace before it goes quiet. */
constexpr std::size_t kSeenCap = 24;

hooking::detour::Handle g_deserHandle{};
hooking::detour::Handle g_rosterHandle{};
std::uintptr_t g_base{};
std::array<std::atomic<std::uint32_t>, kSeenCap> g_deserSeen{};
std::array<std::atomic<std::uint32_t>, kSeenCap> g_rosterSeen{};

using DeserFn = char(__fastcall*)(void*, void*, void*, void*, void*);
using RosterFn = void(__fastcall*)(void*, void*, void*, void*, void*, void*);

/** Logs one caller RVA the first time it is seen in the given table, losing races safely. */
void report(std::array<std::atomic<std::uint32_t>, kSeenCap>& seen,
           const char* stage,
           std::uint32_t rva) noexcept {
    for (std::size_t slot = 0; slot < kSeenCap; ++slot) {
        const std::uint32_t cur = seen[slot].load(std::memory_order_relaxed);
        if (cur == rva) {
            return;
        }
        if (cur == 0) {
            std::uint32_t expected = 0;
            if (!seen[slot].compare_exchange_strong(expected, rva, std::memory_order_relaxed)) {
                --slot;
                continue;
            }
            std::array<char, 96> line{};
            const int written = std::snprintf(
                line.data(), line.size(), "ev=senseconsumer stage=%s caller_rva=0x%08X", stage, rva);
            if (written > 0) {
                core::log::write(core::log::Channel::client,
                                 core::log::Level::info,
                                 {line.data(), static_cast<std::size_t>(written)});
            }
            return;
        }
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
            report(g_deserSeen, "deser", static_cast<std::uint32_t>(caller - g_base));
        }
    }
    return reinterpret_cast<DeserFn>(g_deserHandle.original)(rcx, rdx, r8, r9, stack5);
}

/** Records the dispatcher return address when the roster is decoded, then forwards unchanged. */
__declspec(noinline) void __fastcall roster(void* rcx,
                                            void* rdx,
                                            void* r8,
                                            void* r9,
                                            void* stack5,
                                            void* stack6) noexcept {
    if (g_base != 0) {
        const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
        if (caller > g_base) {
            report(g_rosterSeen, "dispatch", static_cast<std::uint32_t>(caller - g_base));
        }
    }
    reinterpret_cast<RosterFn>(g_rosterHandle.original)(rcx, rdx, r8, r9, stack5, stack6);
}

} // namespace

/**
 * Attaches the sense_update consumer finders.
 * @return True when at least one detour attaches.
 */
bool install_binding_trace() noexcept {
    if (g_deserHandle.attached || g_rosterHandle.attached) {
        return true;
    }
    bool any = false;
    std::byte* const deser = scan_main_image_unique(kDeser, "sense_deserializer");
    if (deser != nullptr) {
        g_base = reinterpret_cast<std::uintptr_t>(deser) - kDeserRva;
        const hooking::detour::Spec spec{deser, reinterpret_cast<void*>(&deserialize)};
        any = hooking::detour::install(spec, g_deserHandle) || any;
    }
    std::byte* const rosterFn = scan_main_image_unique(kRoster, "roster_decoder");
    if (rosterFn != nullptr) {
        g_base = reinterpret_cast<std::uintptr_t>(rosterFn) - kRosterRva;
        const hooking::detour::Spec spec{rosterFn, reinterpret_cast<void*>(&roster)};
        any = hooking::detour::install(spec, g_rosterHandle) || any;
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     any ? "ev=senseconsumer result=ok" : "ev=senseconsumer result=fail");
    return any;
}

/** Detaches the sense_update consumer finders. */
void uninstall_binding_trace() noexcept {
    if (g_deserHandle.attached) {
        (void)hooking::detour::uninstall(g_deserHandle);
    }
    if (g_rosterHandle.attached) {
        (void)hooking::detour::uninstall(g_rosterHandle);
    }
}

} // namespace sunrise::client::hooks::bootflow
