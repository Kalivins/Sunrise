#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "../destination/definition.h"

namespace sunrise::state::activity::defaults {

/** Global activity state reserves 64 one-byte bubble-state entries. */
inline constexpr std::size_t kBubbleCapacity = 64;
/** Each bubble owns 8 consecutive slice-state indices. */
inline constexpr std::size_t kSliceStatesPerBubble = 8;
/** One bubble is needed for a usable locally-authored destination policy. */
inline constexpr std::uint8_t kMinimumBubbleCount = 1;
/** 64 bubbles with 8 states each give a largest valid index of 511. */
inline constexpr std::uint16_t kMaximumInitialSliceSet = 511;

/** Small numeric launch policy paired with the locally-authored default destination. */
struct FallbackPolicy final {
    /** Number of meaningful entries in the fixed bubble-state array. */
    std::uint8_t bubbleCount{};
    /** One bit per bubble; set bits mark entries that publish slice-state zero. */
    std::uint64_t statefulBubbleMask{};
    /** First slice-state index, picked when no earlier source finds one. */
    std::uint16_t initialSliceSet{};
    /** Spawn-set name hash used by the initial slice-state selection. */
    std::uint32_t spawnSetHash{};
};

/** One whole absent-selection fallback without a package-content map. */
struct DefaultDestination final {
    destination::DestinationSelection selection{};
    FallbackPolicy fallback{};
};

/**
 * Destinations that may carry an authored arrival override.
 * A few maps bind their arrival when the map loads instead of declaring it in the packages, so no
 * walk can derive those. The reference set is 20 rows. This leaves room above it.
 */
inline constexpr std::size_t kArrivalOverrideCapacity = 64;

/**
 * One authored arrival for a named destination, applied over every derived source.
 * Neither field is needed. A row may move only the bubble, only the spawn set, or both.
 */
struct ArrivalOverride final {
    std::array<char, destination::kPackageNameCapacity> name{};
    std::uint8_t nameLength{};
    std::uint8_t bubble{};
    bool hasBubble{};
    std::uint32_t spawnSetHash{};
    bool hasSpawnSetHash{};
};

/** Bit-program steps that author a sense_command body after the fixed 128-bit epoch. */
inline constexpr std::size_t kCommandBodyCapacity = 32;

/** One MSB-first field of the settings-authored sense_command bit-program. */
struct CommandBodyStep final {
    std::uint8_t width{};
    std::uint64_t value{};
};

/** Immutable activity defaults supplied while the root State is initialized. */
struct ActivityDefaults final {
    DefaultDestination defaultDestination{};
    std::array<ArrivalOverride, kArrivalOverrideCapacity> arrivalOverrides{};
    std::uint8_t arrivalOverrideCount{};
    /**
     * Sends the membership identity's `field3` as message 5's player key, not the character SOID.
     * That field is the member record's `+16`, which is the value this key must equal.
     */
    bool rosterKeyFromIdentity{};
    /**
     * Fills message 5's participation body on every type-13 slot of the key group.
     * The old encoder fills only the group's first, and the gate reads whichever object the player
     * datum names, which need not be that one.
     */
    bool rosterKeyOnAllSlots{};
    /**
     * DIAGNOSTIC squad.place width search. When enabled, every type-1 (squad) slot's message-5 auth
     * body is written as `squadPlaceValue` on `squadPlaceWidth` bits instead of the seed-only zero
     * it ships today. A wrong width desyncs the phase-2 block stream (the witness). Off by default;
     * a temporary probe to find the real type-1 body width, to be removed.
     */
    bool squadPlaceEnabled{};
    std::uint8_t squadPlaceWidth{};
    std::uint64_t squadPlaceValue{};
    /**
     * DIAGNOSTIC squad.place injection. When squadPlaceEnabled is on, a synthetic top-level roster
     * group is injected carrying one type-1 (squad) auth slot at `squadPlaceIndex`, keyed by
     * `squadPlaceKey`, so a squad's placement slot enters the roster (it is not admitted otherwise).
     * Defaults name Chosen's `squad_ikora` (index 91, registryKey 0xef4eaa1e). Off by default.
     */
    std::uint32_t squadPlaceKey{0xEF4EAA1E};
    std::uint16_t squadPlaceIndex{91};
    /**
     * Region to inject the squad group in. The roster's region is not spatial progression: a whole
     * playthrough reports region 0. -1 (default) injects in every region snapshot, so the group is
     * present in the region 0 the player plays in; a non-negative value scopes it to that region.
     */
    std::int32_t squadPlaceRegion{-1};
    /**
     * Phase-2 command emitter (`sense_update`, message type 6). Type 6 is a server->client command
     * the client parses; it never originates one (measured: an entire mission traversal shows zero
     * inbound type 6). When enabled, the keepalive appends one sense_update whose body is the
     * current 128-bit patch epoch followed by the bits of `commandBody`. That program starts at the
     * delta's presence bit; the delta grammar is resolved (schema 0x80808769, reading (b): every
     * nested field is a presence bit then its content) but the semantics are not, so the body is
     * authored bit by bit to try one layout per boot without a rebuild. Off by default.
     */
    bool commandEmitEnabled{};
    std::array<CommandBodyStep, kCommandBodyCapacity> commandBody{};
    std::uint8_t commandBodyCount{};
    /**
     * DIAGNOSTIC content-load command sweep. When enabled, each keepalive emits a sense_update whose
     * delta is a single record with field 0 (the 13-bit lead field) set to an index that advances by
     * one every send, and the four nested fields authored from commandSweepValue. The binding-creator
     * trace fires if any index makes the client load an object, so one session sweeps the index space
     * while the log correlates the fired index. Overrides commandBody. Off by default.
     */
    bool commandSweepEnabled{};
    std::uint64_t commandSweepValue{};
    /**
     * Incident emitter (message type 19). Unlike the sense_update command (type 6), which the client
     * rejects inbound as "unknown message type", an incident is a server->client gameplay-event
     * trigger the client consumes: its 13-bit primary target indexes the 7,763-record global handler
     * table (spawn rules, spawn sets, encounter directives), which is how the deleted mission
     * director drove spawns/doors/VO. When enabled, each keepalive appends one incident naming
     * `incidentTarget`. With incidentSweepEnabled the target advances by one every send, so one
     * session walks the target space while the witness log correlates the target that produced an
     * effect. Poison (795/4690/5375) and out-of-range (>7762) targets are dropped by the encoder.
     * Off by default.
     */
    bool incidentEmitEnabled{};
    std::uint32_t incidentTarget{};
    bool incidentSweepEnabled{};
    /**
     * Exit-3 auth bodies for two objects the mission mounts natively but that Sunrise leaves
     * bodyless: the activity-script authority (slot type 18, schema 0x80809919) and the mission
     * director (slot type 35, schema 0x808099BF), which share the validity-window block 0x808099C4.
     * These are step-5 instruments: they measure whether the auth-body path reaches a live object,
     * not a spawn (the director owns no spawner). Each body is a settings-authored bit-program so
     * the exact field layout, the validity window, and the bool width can be tuned without a
     * rebuild, and the program's self-consistent bit count can never break the roster encode. Both
     * off by default. An all-zero window decodes to an empty validity range, so a neutral body still
     * needs an explicit window (§29.5).
     */
    bool scriptBodyEnabled{};
    std::array<CommandBodyStep, kCommandBodyCapacity> scriptBody{};
    std::uint8_t scriptBodyCount{};
    bool directorBodyEnabled{};
    std::array<CommandBodyStep, kCommandBodyCapacity> directorBody{};
    std::uint8_t directorBodyCount{};
};

} // namespace sunrise::state::activity::defaults
