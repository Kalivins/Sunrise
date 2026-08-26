#include "bubble_authority_replacements.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <intrin.h>

#include "../../../../core/logging/log.h"
#include "../../../../core/settings/settings.h"
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

/**
 * SEED-DOOR FIELDS, read from the seed machine's own disassembly rather than guessed. The machine
 * tests these two on the same container that holds the masks above:
 *   cmp byte [container+0x18], 0     -> non-zero seeds the lane (a content binding is attached)
 *   call A() && contentUntracked()   -> clears both masks (never taken here: the getter reads false)
 *   cmp dword [container+0x1c], 0x1ff-> at or below seeds the lane, above skips it entirely
 * A skipped lane is neither seeded nor cleared, which is exactly the held lane we keep seeing. Both
 * fields sit far inside an object whose +0x10eb8 masks already read cleanly, so this adds no reach.
 */
constexpr std::size_t kBindingOffset = 0x18;
constexpr std::size_t kLoadCounterOffset = 0x1c;
constexpr std::uint32_t kLoadCounterDoor = 0x1ff;
/** The content object the binding creator attaches, written beside the binding byte it sets. */
constexpr std::size_t kContentObjectOffset = 0x10;
std::atomic<unsigned> g_lastRegistered{0xFFFFFFFFU};
std::atomic<unsigned> g_lastSeeded{0xFFFFFFFFU};
std::atomic<std::uint32_t> g_lastCounter{0xFFFFFFFFU};

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
    unsigned binding = 0;
    std::uint32_t loadCounter = 0;
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
        binding = base[kBindingOffset];
        loadCounter = *reinterpret_cast<const std::uint32_t*>(base + kLoadCounterOffset);
    } __except (1) {
        return;
    }
    if (registered == g_lastRegistered.load(std::memory_order_relaxed)
        && seeded == g_lastSeeded.load(std::memory_order_relaxed)
        && loadCounter == g_lastCounter.load(std::memory_order_relaxed)) {
        return;
    }
    g_lastRegistered.store(registered, std::memory_order_relaxed);
    g_lastSeeded.store(seeded, std::memory_order_relaxed);
    g_lastCounter.store(loadCounter, std::memory_order_relaxed);
    std::array<char, 160> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=bubbleauth stage=seed registered=%u seeded=%u held=%d reg0=0x%08X seed0=0x%08X "
        "binding=%u counter=%u door_binding=%d door_counter=%d",
        registered,
        seeded,
        static_cast<int>(registered) - static_cast<int>(seeded),
        registeredWords[0],
        seededWords[0],
        binding,
        loadCounter,
        binding != 0 ? 1 : 0,
        loadCounter <= kLoadCounterDoor ? 1 : 0);
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
using SquadAuthorityGate = bool(__fastcall*)();
using SquadAuthorityResolver = void*(__fastcall*)(void*);

/**
 * Opens the seed machine's first door, behind reconstruct_mission_policy so it is off by default.
 *
 * The machine seeds a lane when `byte[container+0x18]` is non-zero, and otherwise falls through to a
 * load counter that reads -1 here, which skips the lane and leaves it held forever. Measurement shows
 * the binding byte is always zero: no content object is bound to the held bubble. Writing the byte
 * tells the client a binding exists.
 *
 * That is a lie the client can act on, so it is guarded: the write happens only when the container
 * already carries a content-object pointer at +0x10. With a real object present, claiming it is bound
 * is a far smaller step than inventing one, and a null pointer would be the crash this guard exists
 * to avoid. The state written is the client's own, and a fresh decode rebuilds it.
 * @param roster Decoded roster container.
 */
void try_open_seed_door(void* roster) noexcept {
    if (roster == nullptr || !core::settings::get().server.activation.reconstructMissionPolicy) {
        return;
    }
    static std::atomic_bool g_doorReported{false};
    const void* content = nullptr;
    unsigned before = 0;
    std::uint32_t counterBefore = 0;
    bool wrote = false;
    __try {
        auto* base = static_cast<std::uint8_t*>(roster);
        content = *reinterpret_cast<void* const*>(base + kContentObjectOffset);
        before = base[kBindingOffset];
        if (content != nullptr && before == 0) {
            base[kBindingOffset] = 1;
            wrote = true;
        }
        // The seed machine tests two fields, not one. With the binding byte set the lane still
        // reads its load counter, and a value above the door makes the machine skip the lane
        // outright: neither seeded nor cleared, which is the held lane. Every measured run reports
        // 0xFFFFFFFF here, so the second test never passes and forcing only the first changes
        // nothing. Bring the counter under the door on the same guard as the binding: a real
        // content object is attached, so the lane has something to seed.
        counterBefore = *reinterpret_cast<const std::uint32_t*>(base + kLoadCounterOffset);
        if (content != nullptr && counterBefore > kLoadCounterDoor) {
            *reinterpret_cast<std::uint32_t*>(base + kLoadCounterOffset) = 0;
            wrote = true;
        }
    } __except (1) {
        return;
    }
    if (g_doorReported.exchange(true, std::memory_order_relaxed)) {
        return;
    }
    std::array<char, 160> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=bubbleauth stage=door result=%s content=%p binding=%u "
                                      "counter=%u",
                                      wrote ? "opened" : "held",
                                      content,
                                      before,
                                      counterBefore);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

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
        // Before the native decode, so the byte is already set when the seed machine consults it.
        try_open_seed_door(roster);
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

/**
 * Reports the squad-authority gate, and opens it only when the setting asks.
 *
 * Both squad-authority entry points consult this predicate and return immediately when it answers
 * true, so a true answer is enough to explain a mission whose squads never place. The predicate
 * reads an obfuscated singleton that resolves only at runtime, which is why this is measured rather
 * than read. The witness runs whatever the setting says, so one build answers both questions: what
 * the client thinks, and what changes when it thinks otherwise.
 * @return Native answer, or false when the setting forces the gate open.
 */
__declspec(noinline) bool __fastcall squad_authority_gate_body() noexcept {
    coordinator::CallLease lease{};
    coordinator::g_callIngress(lease, HookSlot::squadAuthorityGate, coordinator::ConsumerKind::none);
    const auto call = reinterpret_cast<SquadAuthorityGate>(lease.original);
    bool result{};
    __try {
        if (call != nullptr) {
            result = call();
        }
        static std::atomic_bool g_gateSeen{false};
        const bool forced = result && core::settings::get().server.activation.squadGateForceOpen;
        if (!g_gateSeen.exchange(true, std::memory_order_relaxed)) {
            std::array<char, 96> line{};
            const int written = std::snprintf(line.data(),
                                              line.size(),
                                              "ev=bubbleauth stage=squadgate native=%u forced=%u",
                                              static_cast<unsigned>(result),
                                              static_cast<unsigned>(forced));
            if (written > 0) {
                core::log::write(core::log::Channel::client,
                                 core::log::Level::info,
                                 {line.data(), static_cast<std::size_t>(written)});
            }
        }
        if (forced) {
            result = false;
        }
    } __finally {
        coordinator::g_callEgress();
    }
    return result;
}

/**
 * Reports whether the squad-authority resolver runs, who called it, and whether it found an object.
 *
 * Every authority published this session assumes this path runs; nothing has measured that. The
 * return address separates the consumer the encoder names from the other caller, and a null result
 * means the consumer takes its fallback branch rather than the resolved-object one. Bounded to a few
 * lines so a per-frame call cannot flood the log.
 * @param owner Whatever the caller is looking the object up for.
 * @return The native answer, unchanged.
 */
__declspec(noinline) void* __fastcall squad_authority_resolver_body(void* owner) noexcept {
    // The trampoline is resolved once and then called directly. Going through the coordinator on
    // every call throttled the load enough to hang it: this runs inside the roster decode, which
    // already holds a lease, so each call contended with the scope that invoked it.
    static std::atomic<void*> g_original{nullptr};
    auto trampoline =
        reinterpret_cast<SquadAuthorityResolver>(g_original.load(std::memory_order_relaxed));
    if (trampoline == nullptr) {
        coordinator::CallLease lease{};
        coordinator::g_callIngress(
            lease, HookSlot::squadAuthorityResolver, coordinator::ConsumerKind::none);
        trampoline = reinterpret_cast<SquadAuthorityResolver>(lease.original);
        if (trampoline != nullptr) {
            g_original.store(reinterpret_cast<void*>(trampoline), std::memory_order_relaxed);
        }
        coordinator::g_callEgress();
    }
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    void* result = nullptr;
    __try {
        if (trampoline != nullptr) {
            result = trampoline(owner);
        }
    } __except (1) {
        return nullptr;
    }
    // One line per distinct caller, not per call. A per-call budget spends itself on whichever
    // caller runs first and never shows the other, which is the open question here: whether the
    // consumer the encoder names reaches this at all.
    static std::array<std::atomic<std::uint32_t>, 8> g_seenCallers{};
    static std::atomic<unsigned> g_seenCount{0};
    const std::uintptr_t base = g_imageBase.load(std::memory_order_relaxed);
    const auto rva = static_cast<std::uint32_t>(base != 0 ? caller - base : 0);
    const unsigned count = g_seenCount.load(std::memory_order_relaxed);
    for (unsigned index = 0; index < count; ++index) {
        if (g_seenCallers[index].load(std::memory_order_relaxed) == rva) {
            return result;
        }
    }
    if (count >= g_seenCallers.size()) {
        return result;
    }
    g_seenCallers[count].store(rva, std::memory_order_relaxed);
    g_seenCount.store(count + 1, std::memory_order_relaxed);
    std::array<char, 128> line{};
    const int written =
        std::snprintf(line.data(),
                      line.size(),
                      "ev=bubbleauth stage=squadresolve caller=0x%08X owner=%p found=%u",
                      rva,
                      owner,
                      static_cast<unsigned>(result != nullptr));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

} // namespace

/** @return The internal-linkage squad-resolver body, kept safe while the detour is removed. */
void* squad_authority_resolver_entry_point() noexcept {
    return reinterpret_cast<void*>(&squad_authority_resolver_body);
}

/** @return The internal-linkage squad-authority gate body, kept safe while the detour is removed. */
void* squad_authority_gate_entry_point() noexcept {
    return reinterpret_cast<void*>(&squad_authority_gate_body);
}

/** @return The internal-linkage decoder body, kept safe while the detour is removed. */
void* decoder_entry_point() noexcept {
    return reinterpret_cast<void*>(&decoder_body);
}

/** @return The internal-linkage getter body, kept safe while the detour is removed. */
void* content_untracked_entry_point() noexcept {
    return reinterpret_cast<void*>(&content_untracked_body);
}

} // namespace sunrise::client::hooks::network::bubble_authority
