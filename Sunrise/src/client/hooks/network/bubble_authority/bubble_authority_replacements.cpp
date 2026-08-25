#include "bubble_authority_replacements.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <intrin.h>

#include "../../../../core/logging/log.h"
#include "../coordinator/network_call_coordinator.h"
#include "../platform.h"
#include "scope/bubble_authority_scope.h"

namespace sunrise::client::hooks::network::bubble_authority {
namespace {

/** Log the decoder and the forced arm once each. Both run on every roster message. */
std::atomic_bool g_decoderSeen{false};
std::atomic_bool g_forcedSeen{false};

/** SEED WITNESS (diagnostic): the roster's registered and seeded lane masks, whose relative offsets
 *  the apply function reads. A lane is held when registered but not seeded, so comparing the two
 *  popcounts after a decode says whether the published object lanes actually seed. */
constexpr std::size_t kRegisteredMaskOffset = 0x10eb8;
constexpr std::size_t kSeededMaskOffset = 0x10ec4;
constexpr std::size_t kMaskWords = 4;
std::atomic<unsigned> g_lastRegistered{0xFFFFFFFFU};
std::atomic<unsigned> g_lastSeeded{0xFFFFFFFFU};

/**
 * CALL-SITE WITNESS (diagnostic). The native seed machine clears a lane's seed when the
 * content-untracked getter reads true, and this hook forces exactly that value true so the bubble
 * authority applies at all. The first `stage=force` line already proves the client's own answer is
 * false, so the force is what shuts the seed door. Both consumers sit inside one decoder scope, so
 * the force cannot be narrowed until their call sites are told apart. Record each distinct return
 * address that consults the getter, as an image RVA, with the native answer and whether the scope
 * was forcing. Return addresses are only subtracted and logged, never dereferenced.
 */
constexpr std::size_t kCallSiteCapacity = 8;
std::array<std::atomic<std::uint32_t>, kCallSiteCapacity> g_callSiteRva{};
std::atomic<unsigned> g_callSiteCount{0};
/** Client image base, resolved once, so a return address becomes a stable RVA. */
std::atomic<std::uintptr_t> g_imageBase{0};

/** @return Set-bit count of a 32-bit word. */
[[nodiscard]] unsigned popcount32(std::uint32_t value) noexcept {
    unsigned count = 0;
    while (value != 0) {
        value &= value - 1;
        ++count;
    }
    return count;
}

/** Reads both lane masks from the decoded roster and logs registered vs seeded when either changes. */
void report_seed(const void* roster) noexcept {
    if (roster == nullptr) {
        return;
    }
    unsigned registered = 0;
    unsigned seeded = 0;
    std::uint32_t registeredWords[kMaskWords] = {};
    std::uint32_t seededWords[kMaskWords] = {};
    __try {
        const auto* base = static_cast<const std::uint8_t*>(roster);
        const auto* registeredMask =
            reinterpret_cast<const std::uint32_t*>(base + kRegisteredMaskOffset);
        const auto* seededMask = reinterpret_cast<const std::uint32_t*>(base + kSeededMaskOffset);
        for (std::size_t word = 0; word < kMaskWords; ++word) {
            registeredWords[word] = registeredMask[word];
            seededWords[word] = seededMask[word];
            registered += popcount32(registeredWords[word]);
            seeded += popcount32(seededWords[word]);
        }
    } __except (1) {
        return;
    }
    if (registered == g_lastRegistered.load(std::memory_order_relaxed)
        && seeded == g_lastSeeded.load(std::memory_order_relaxed)) {
        return;
    }
    g_lastRegistered.store(registered, std::memory_order_relaxed);
    g_lastSeeded.store(seeded, std::memory_order_relaxed);
    std::array<char, 160> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=bubbleauth stage=seed registered=%u seeded=%u held=%d reg0=0x%08X reg1=0x%08X "
        "seed0=0x%08X seed1=0x%08X",
        registered,
        seeded,
        static_cast<int>(registered) - static_cast<int>(seeded),
        registeredWords[0],
        registeredWords[1],
        seededWords[0],
        seededWords[1]);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * Records one distinct getter call site as an image RVA, with the native answer and scope state.
 * @param caller Return address of the native code that consulted the getter.
 * @param nativeValue What the client's own getter answered, before any force.
 * @param inScope Whether the decoder scope was forcing when this site asked.
 */
void report_call_site(std::uintptr_t caller, bool nativeValue, bool inScope) noexcept {
    std::uintptr_t base = g_imageBase.load(std::memory_order_relaxed);
    if (base == 0) {
        base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        g_imageBase.store(base, std::memory_order_relaxed);
    }
    if (base == 0 || caller <= base) {
        return;
    }
    const auto rva = static_cast<std::uint32_t>(caller - base);
    const unsigned known = g_callSiteCount.load(std::memory_order_relaxed);
    for (unsigned index = 0; index < known && index < kCallSiteCapacity; ++index) {
        if (g_callSiteRva[index].load(std::memory_order_relaxed) == rva) {
            return;
        }
    }
    if (known >= kCallSiteCapacity) {
        return;
    }
    g_callSiteRva[known].store(rva, std::memory_order_relaxed);
    g_callSiteCount.store(known + 1, std::memory_order_relaxed);
    std::array<char, 160> line{};
    const int written =
        std::snprintf(line.data(),
                      line.size(),
                      "ev=bubbleauth stage=callsite n=%u rva=0x%08X native=%d scope=%d",
                      known,
                      rva,
                      nativeValue ? 1 : 0,
                      inScope ? 1 : 0);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * Logs the first roster decode and the first forced authority read. The forced read is what makes
 * message 5's per-bubble authority arm apply at all. Without it the client keeps its own build
 * state and only the unusable bubble applies.
 * @param stage Which event this is.
 */
void report_once(const char* stage) noexcept {
    std::array<char, 96> line{};
    const int written =
        std::snprintf(line.data(), line.size(), "ev=bubbleauth stage=%s result=ok", stage);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

using Decoder = bool(__fastcall*)(void*, void*, void*);
using ContentUntracked = bool(__fastcall*)();

/**
 * Runs the native roster-prefix decoder inside one thread-local authority scope.
 * @param roster Client roster container borrowed by the native decoder.
 * @param bitStream Native bit reader borrowed for this call.
 * @param event Native activity message storage borrowed for this call.
 * @return The native decoder result, or false when there is no original to call.
 */
__declspec(noinline) bool __fastcall decoder_body(void* roster,
                                                  void* bitStream,
                                                  void* event) noexcept {
    coordinator::CallLease lease{};
    coordinator::g_callIngress(
        lease, HookSlot::bubbleAuthorityDecoder, coordinator::ConsumerKind::none);
    const auto call = reinterpret_cast<Decoder>(lease.original);
    const bool scoped = lease.accepting && call != nullptr;
    bool result{};
    if (scoped) {
        scope::enter();
        if (!g_decoderSeen.exchange(true, std::memory_order_relaxed)) {
            report_once("decode");
        }
    }
    __try {
        if (call != nullptr) {
            result = call(roster, bitStream, event);
        }
    } __finally {
        if (scoped) {
            scope::leave();
        }
        coordinator::g_callEgress();
    }
    if (scoped) {
        report_seed(roster);
    }
    return result;
}

/**
 * Keeps the native build-state read, and forces it true only on the scoped decoder thread.
 * @return Native state, or true only inside an admitted authority decoder call.
 */
__declspec(noinline) bool __fastcall content_untracked_body() noexcept {
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    coordinator::CallLease lease{};
    coordinator::g_callIngress(
        lease, HookSlot::contentUntrackedGetter, coordinator::ConsumerKind::none);
    const auto call = reinterpret_cast<ContentUntracked>(lease.original);
    bool result{};
    __try {
        if (call != nullptr) {
            result = call();
        }
        // Record which native code asked, with the answer it would have received. The seed machine
        // and the authority apply both consult this getter inside one decoder scope, so their call
        // sites are what tells them apart before the force can be narrowed to only the apply.
        const bool active = scope::active();
        report_call_site(caller, result, active);
        const bool forced = !result && active;
        result = result || forced;
        if (forced && !g_forcedSeen.exchange(true, std::memory_order_relaxed)) {
            report_once("force");
        }
    } __finally {
        coordinator::g_callEgress();
    }
    return result;
}

} // namespace

/** @return The internal-linkage decoder body, kept safe while the detour is removed. */
void* decoder_entry_point() noexcept {
    return reinterpret_cast<void*>(&decoder_body);
}

/** @return The internal-linkage getter body, kept safe while the detour is removed. */
void* content_untracked_entry_point() noexcept {
    return reinterpret_cast<void*>(&content_untracked_body);
}

} // namespace sunrise::client::hooks::network::bubble_authority
