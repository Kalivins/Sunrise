#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../../state/activity/runtime.h"
#include "../../hooking/detour.h"
#include "internal.h"
#include "spawn/probe.h"

namespace sunrise::client::hooks::bootflow {
namespace {

/**
 * The player spawn gate. Anchored on the load of the encrypted manager global, then run on
 * through the stack-cookie store because the wildcarded frame size leaves the head too short.
 */
constexpr std::string_view kSpawnGateSignatureText =
    "40 53 57 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 8B D9 "
    "40 B7 01";
/** Compiled pattern bytes of the signature text above. */
constexpr auto kSpawnGateSignature =
    signature<signature_length(kSpawnGateSignatureText)>(kSpawnGateSignatureText);

/** Answer that holds the spawn for this tick. The gate is polled, so a refusal only delays it. */
constexpr bool kHeld = false;

using SpawnGate = bool(__fastcall*)(std::int32_t) noexcept;

hooking::detour::Handle g_handle{};
std::atomic<SpawnGate> g_original{nullptr};

/** Refusal already named, so one reason is written once rather than every polled tick. */
std::atomic<spawn::Refusal> g_reportedRefusal{spawn::Refusal::none};
/** Ticks between two probe passes, which bounds what naming a refusal costs the gate. */
constexpr std::uint64_t kProbeIntervalMs = 1000;
/** Tick the last probe pass ran on. */
std::atomic_uint64_t g_probedTick{};
/** Ticks between two reports of one unchanged reason, so a hold that persists stays visible. */
constexpr std::uint64_t kRepeatIntervalMs = 10000;
/** Tick the last line was written on. */
std::atomic_uint64_t g_reportedTick{};

/**
 * Names the gate condition that refused.
 * The gate answers with one bit, so a hold that never resolves says nothing about which of its
 * eight conditions is holding it. The probe re-runs them in order and the reason is written when
 * it changes, which separates a destination that cannot spawn from one that is still loading.
 * @param datum Player datum handle the gate was called with.
 */
void report_refusal(std::int32_t datum) noexcept {
    const std::uint64_t now = GetTickCount64();
    const std::uint64_t probed = g_probedTick.load(std::memory_order_relaxed);
    if (probed != 0 && now - probed < kProbeIntervalMs) {
        return;
    }
    g_probedTick.store(now, std::memory_order_relaxed);
    const spawn::Reading reading = spawn::examine(datum);
    const spawn::Refusal previous =
        g_reportedRefusal.exchange(reading.refusal, std::memory_order_relaxed);
    const std::uint64_t reported = g_reportedTick.load(std::memory_order_relaxed);
    // A new reason is written at once. An unchanged one repeats on a long interval, because a
    // hold that never resolves is the case worth seeing and it would otherwise say nothing after
    // its first line.
    if (previous == reading.refusal && reported != 0 && now - reported < kRepeatIntervalMs) {
        return;
    }
    g_reportedTick.store(now, std::memory_order_relaxed);
    std::array<char, core::log::kLineCapacity> line{};
    const int head =
        std::snprintf(line.data(), line.size(), "ev=bootflow stage=spawn_gate result=held ");
    if (head <= 0) {
        return;
    }
    const auto offset = static_cast<std::size_t>(head);
    const std::size_t tail = spawn::describe(reading, std::span(line).subspan(offset));
    if (tail == 0) {
        return;
    }
    core::log::write(
        core::log::Channel::client, core::log::Level::info, {line.data(), offset + tail});
}

/**
 * Puts the spawn after the world-transition fade is armed.
 * A release on a channel that is not up does nothing, so a spawn during the load leaves the
 * screen black. The client's own predicate reads a host field this destination never fills.
 * @param datum Borrowed player datum handle; the answer does not depend on it.
 * @return The native answer, or held while a destination load is still running.
 */
__declspec(noinline) bool __fastcall spawn_gate(std::int32_t datum) noexcept {
    const SpawnGate original = g_original.load(std::memory_order_acquire);
    const bool allowed = original != nullptr && original(datum);
    observe_world_step();
    const state::activity::WorldPhase phase = state::activity::world_phase();
    const bool transitioning = phase == state::activity::WorldPhase::transitioning;
    // Zero unless a load is running.
    const std::uint64_t age = state::activity::world_transition_age();
    const core::settings::client::Settings& client = core::settings::get().client;
    const bool gaveUp = age >= client.spawnHoldMs;
    const bool loading = transitioning && !gaveUp && client.holdSpawn;
    // Release only on arrival. The step-37 exit re-arms the fade unless one is already up, and
    // nothing polls this gate after the spawn, so an early release leaves a fade nobody clears.
    if (phase == state::activity::WorldPhase::arrived) {
        release_world_fade();
        // The next load starts from no reason, so its own first refusal is written.
        g_reportedRefusal.store(spawn::Refusal::none, std::memory_order_relaxed);
        g_probedTick.store(0, std::memory_order_relaxed);
        g_reportedTick.store(0, std::memory_order_relaxed);
    }
    if (!allowed) {
        report_refusal(datum);
    }
    return allowed && loading ? kHeld : allowed;
}

} // namespace

/** Attaches the spawn hold. */
bool install_spawn_hold() noexcept {
    if (g_handle.attached) {
        return true;
    }
    std::byte* const target = scan_main_image_unique(kSpawnGateSignature, "player_spawn_gate");
    if (target == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=spawn_hold result=fail reason=target");
        return false;
    }
    const hooking::detour::Spec spec{target, reinterpret_cast<void*>(&spawn_gate)};
    if (!hooking::detour::install(spec, g_handle)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=spawn_hold result=fail reason=attach");
        return false;
    }
    g_original.store(reinterpret_cast<SpawnGate>(g_handle.original), std::memory_order_release);
    // The probe reads the gate's own predicates out of its body, so it needs the base the scan
    // found. A failure there only costs the refusal name; the hold itself still works.
    if (!spawn::resolve(target)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=spawn_probe result=fail reason=predicates");
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=bootflow stage=spawn_hold result=ok");
    return true;
}

/** Detaches the spawn hold. */
void uninstall_spawn_hold() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
    g_original.store(nullptr, std::memory_order_release);
    spawn::forget();
}

} // namespace sunrise::client::hooks::bootflow
