#include "bubble_authority_replacements.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>

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
 * SEED-DOOR WITNESS (diagnostic). The native seed machine sets a lane's seeded bit through one of
 * three doors, and otherwise clears it:
 *   byte[obj+0x18] != 0                      -> seed set   (the binding indicator)
 *   A() && contentUntracked()                -> CLEAR      (what we hit today: we force the getter
 *                                                           true so the bubble applies at all)
 *   [obj+0x1c] <= 0x1ff                      -> seed set
 * The held lanes never reach a door, so read the two fields the doors test on the lane objects the
 * roster holds, plus the native (unforced) content-untracked value. That says which door is within
 * reach instead of guessing. Offsets are lane-object relative; the lane table pointer sits in the
 * roster container next to the masks. Read defensively: any bad pointer aborts the witness.
 */
constexpr std::size_t kLaneTableOffset = 0x10eb0;
constexpr std::size_t kBindingIndicatorOffset = 0x18;
constexpr std::size_t kLoadCounterOffset = 0x1c;
constexpr std::size_t kLoadCounterDoor = 0x1ff;
/** Report the door state a bounded number of times, so a per-message hook cannot flood the log. */
std::atomic<unsigned> g_doorReports{0};
constexpr unsigned kMaxDoorReports = 12;
/** Native content-untracked value, captured before the decoder scope forces it true. */
std::atomic<int> g_nativeUntracked{-1};

/** Defined below; reports which seed door the held lanes can reach. */
void report_doors(const void* roster, int held) noexcept;

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
    report_doors(roster, static_cast<int>(registered) - static_cast<int>(seeded));
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
 * Reports the seed-door state for the roster's lane objects while any lane is held. Reads only the
 * two fields the seed machine tests, and the native content-untracked value captured before the
 * decoder forces it. Every dereference is guarded, and a null or unreadable pointer ends the report
 * rather than risking the decode path.
 * @param roster Decoded roster container.
 * @param held How many lanes are registered but not seeded.
 */
void report_doors(const void* roster, int held) noexcept {
    if (roster == nullptr || held <= 0
        || g_doorReports.fetch_add(1, std::memory_order_relaxed) >= kMaxDoorReports) {
        return;
    }
    const void* lane = nullptr;
    unsigned indicator = 0;
    unsigned counter = 0;
    bool read = false;
    __try {
        const auto* base = static_cast<const std::uint8_t*>(roster);
        lane = *reinterpret_cast<void* const*>(base + kLaneTableOffset);
        if (lane != nullptr) {
            const auto* laneBytes = static_cast<const std::uint8_t*>(lane);
            indicator = laneBytes[kBindingIndicatorOffset];
            counter = *reinterpret_cast<const std::uint32_t*>(laneBytes + kLoadCounterOffset);
            read = true;
        }
    } __except (1) {
        return;
    }
    std::array<char, 200> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=bubbleauth stage=doors held=%d lane=%p read=%d indicator=%u counter=0x%X "
        "door_binding=%d door_counter=%d native_untracked=%d",
        held,
        lane,
        read ? 1 : 0,
        indicator,
        counter,
        read && indicator != 0 ? 1 : 0,
        read && counter <= kLoadCounterDoor ? 1 : 0,
        g_nativeUntracked.load(std::memory_order_relaxed));
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
    coordinator::CallLease lease{};
    coordinator::g_callIngress(
        lease, HookSlot::contentUntrackedGetter, coordinator::ConsumerKind::none);
    const auto call = reinterpret_cast<ContentUntracked>(lease.original);
    bool result{};
    __try {
        if (call != nullptr) {
            result = call();
        }
        // Capture the NATIVE value before the force below. The seed machine clears a lane's seed when
        // this reads true, so knowing what the client would answer on its own says whether the
        // content-untracked door is even a candidate, or whether our force is the only reason it shuts.
        g_nativeUntracked.store(result ? 1 : 0, std::memory_order_relaxed);
        const bool forced = !result && scope::active();
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
