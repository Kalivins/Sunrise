#include "sensor_auth_update.h"

namespace sunrise::middleware::bap::activity_message::sensor_auth_update {
namespace {

namespace bits = encoding::bits;

/** Slot types whose auth body this module fills. Every other block is seed-only. */
constexpr std::uint8_t kSlotTypeSquad = 1;
constexpr std::uint8_t kSlotTypeParticipation = 13;
constexpr std::uint8_t kSlotTypeLifetime = 17;
constexpr std::uint8_t kSlotTypeConfiguration = 8;
constexpr std::uint8_t kSlotTypePackage = 16;
constexpr std::uint8_t kSlotTypeQueues = 41;
constexpr std::uint8_t kSlotTypeSpawnKeys = 67;
/** Exit-3 targets: mounted natively, bodyless in Sunrise, filled from a settings bit-program. */
constexpr std::uint8_t kSlotTypeScript = 18;
constexpr std::uint8_t kSlotTypeDirector = 35;

/** Body widths, each checked against the writer after the body is written. */
constexpr std::size_t kParticipationBits = 192;
constexpr std::size_t kParticipationRegionBits = 32;
constexpr std::size_t kLifetimeBits = 520;
constexpr std::size_t kConfigurationBits = 35;
constexpr std::size_t kPackageBits = 7;
constexpr std::size_t kQueueBits = 12;
constexpr std::size_t kSpawnKeyBits = 32 * 32 + 1 + 32;

/** Signed fields in these bodies carry a -2^31 bias, so this wire value stores zero. */
constexpr std::uint32_t kSignedZero = 0x80000000;
/** The same bias wraps at the top of the field, so this wire value stores -1. */
constexpr std::uint32_t kSignedMinusOne = 0x7FFFFFFF;
/** The region index rides the same bias, so its wire value is the bias plus the index. */
constexpr std::uint32_t kRegionBias = 0x80000000;
/** Message 52's team-state byte 1, where bit 1 is `awaiting_client_sync`. */
constexpr std::uint32_t kAwaitingClientSync = 2;
/** Neutral runtime-i32 override that forces the type-17 waiting selector to zero. */
constexpr std::uint32_t kWaitingSwitchKey = 0xB3C1251B;
constexpr std::uint32_t kWaitingSwitchClass = 0x80800007;
/** Type 17 carries 3 spawn overrides. Wire zero stores index -1 and disables one. */
constexpr std::size_t kSpawnOverrideCount = 3;
constexpr std::uint8_t kSpawnOverrideIndexWidth = 10;
constexpr std::uint32_t kSpawnOverrideIndexBias = 1;
/** Type 67 maps the 32 spawn-key ordinals to themselves, matching its constructor. */
constexpr std::size_t kSpawnKeyCount = 32;
/** Type 1 (squad) minimal 0x80807ec9 body (M1 first pass): every optional absent, so the client
 * instantiates the squad from its own authored placement instead of a body-carried one. 18 presence
 * bits, a 2-bit and a 3-bit fixed field, then one presence bit. */
constexpr std::size_t kSquadBodyBits = 18 + 2 + 3 + 1;

/**
 * Writes the participation body, which binds the player and latches the region. Zero-fill is not
 * safe here. Every biased field must carry its bias, or a stored zero decodes to the smallest
 * signed value.
 * @param writer Body writer.
 * @param snapshot Message input.
 * @return True when the body fits.
 */
[[nodiscard]] bool write_participation(bits::Writer& writer, const Snapshot& snapshot) noexcept {
    // An optional field's value follows its presence bit, so sending +0 shifts everything below.
    bool encoded = writer.write(snapshot.hasRegion ? 1U : 0U, kPresenceWidth);
    if (encoded && snapshot.hasRegion) {
        encoded = writer.write(kRegionBias + snapshot.region, kParticipationRegionBits);
    }
    // The participation record is this body's head, so struct +8 and +10 are record +8 and +10.
    // Record +8 is step 36 task 9's own term and +10 is the spawn gate's.
    return encoded && writer.write(0, kPresenceWidth) && writer.write(1, kPresenceWidth)
           && writer.write(1, kPresenceWidth) && writer.write(1, kPresenceWidth)
           && writer.write(0, kPresenceWidth) && writer.write(1, 3) && writer.write(1, 2)
           && writer.write(0, 3) && writer.write(0, 32) && writer.write(1, 5)
           && writer.write(0, kPresenceWidth) && writer.write(0, 3)
           && writer.write(1, kPresenceWidth) && writer.write(snapshot.playerKey, 64)
           && writer.write(0, 5) && writer.write(3, 6) && writer.write(0, 6)
           && writer.write(0, 6)
           // Byte 736 skips the respawn delay, whose countdown never expires when the content
           // delay is negative. Byte 737 holds the spawn while the client loads.
           && writer.write(1, kPresenceWidth)
           && writer.write(snapshot.awaitClientSync ? kAwaitingClientSync : 0U, 4)
           && writer.write(0, 3) && writer.write(0, kPresenceWidth) && writer.write(128, 8)
           && writer.write(kSignedZero, 32);
}

/**
 * Writes the lifetime body, which is the activity state the roster reports.
 * @param writer Body writer.
 * @param snapshot Message input.
 * @return True when the body fits.
 */
[[nodiscard]] bool write_lifetime(bits::Writer& writer, const Snapshot& snapshot) noexcept {
    bool encoded = writer.write(std::uint32_t{snapshot.lifetime} + 1, 4) && writer.write(1, 3)
                   && writer.write(0, kPresenceWidth) && writer.write(kSignedZero, 32)
                   && writer.write(0, 32) && writer.write(kSignedZero, 32) && writer.write(1, 6)
                   && writer.write(kWaitingSwitchKey, 32) && writer.write(1, kPresenceWidth)
                   && writer.write(kWaitingSwitchClass, 32) && writer.write(kSignedZero, 32)
                   && writer.write(kSignedZero, 32);
    for (std::size_t index = 0; encoded && index < kSpawnOverrideCount; ++index) {
        const std::uint32_t slice =
            snapshot.hasSpawnOverride ? snapshot.spawnSliceSet + kSpawnOverrideIndexBias : 0U;
        const std::uint32_t hash =
            snapshot.hasSpawnOverride ? snapshot.spawnSetHash : kAbsentSpawnSetHash;
        encoded = writer.write(slice, kSpawnOverrideIndexWidth) && writer.write(hash, 32);
    }
    // Struct `+1256` is the out-of-bounds `activity_quarantine` selector. The reader arms the
    // quarantine at or below 0x3F unsigned, so minus one leaves it clear and teleports nobody.
    return encoded && writer.write(0, kPresenceWidth) && writer.write(0, 32)
           && writer.write(kSignedMinusOne, 32) && writer.write(0, 32)
           && writer.write(kSlotTypeBias, kSlotTypeWidth)
           && writer.write(kSlotIndexBias, kSlotIndexWidth) && writer.write(0, 32)
           && writer.write(0, 3);
}

/** Number of valid steps in a body program, clamped to its fixed storage. */
[[nodiscard]] std::size_t program_count(std::uint8_t count, std::size_t capacity) noexcept {
    return count <= capacity ? count : capacity;
}

/** Sums the widths of an auth-body bit-program. */
[[nodiscard]] std::size_t program_bits(const BodyStep* steps, std::size_t count) noexcept {
    std::size_t total = 0;
    for (std::size_t index = 0; index < count; ++index) {
        total += steps[index].width;
    }
    return total;
}

/** Writes an auth-body bit-program, most significant field first. */
[[nodiscard]] bool write_program(bits::Writer& writer,
                                 const BodyStep* steps,
                                 std::size_t count) noexcept {
    bool encoded = true;
    for (std::size_t index = 0; encoded && index < count; ++index) {
        encoded = writer.write(steps[index].value, steps[index].width);
    }
    return encoded;
}

/**
 * Writes the spawn-key body, which maps the 32 ordinals to themselves.
 * @param writer Body writer.
 * @return True when the body fits.
 */
[[nodiscard]] bool write_spawn_keys(bits::Writer& writer) noexcept {
    bool encoded = true;
    for (std::size_t index = 0; encoded && index < kSpawnKeyCount; ++index) {
        encoded = writer.write(kSignedZero + index, 32);
    }
    return encoded && writer.write(0, kPresenceWidth) && writer.write(kSignedMinusOne, 32);
}

} // namespace

/** Reports how many bits of auth body one slot carries. */
std::size_t
auth_body_bits(const Snapshot& snapshot, std::uint8_t slotType, bool carriesPlayerKey) noexcept {
    if (slotType == kSlotTypeParticipation) {
        return carriesPlayerKey
                   ? kParticipationBits + (snapshot.hasRegion ? kParticipationRegionBits : 0)
                   : 0;
    }
    if (slotType == kSlotTypeLifetime) {
        return kLifetimeBits;
    }
    if (slotType == kSlotTypeConfiguration) {
        return kConfigurationBits;
    }
    if (slotType == kSlotTypePackage) {
        return kPackageBits;
    }
    if (slotType == kSlotTypeQueues) {
        return kQueueBits;
    }
    if (slotType == kSlotTypeSpawnKeys) {
        return kSpawnKeyBits;
    }
    // squad.place body: the type-1 slot's authSchema 0x80807ec9, RE'd by emulating the schema
    // deserializer 0x4c74b0. The placement form presents field 0 (a slot reference), the field the
    // consumer (0x1703d70) reads to drive its placement branch; see kSquadBodyBits.
    if (slotType == kSlotTypeSquad && snapshot.squadPlaceEnabled) {
        return kSquadBodyBits;
    }
    // Exit-3 auth bodies. These slots are mounted natively and ship bodyless today; when enabled
    // they carry a settings-authored bit-program. The count equals what write_auth_body emits, so
    // the block's remainder frames it exactly.
    if (slotType == kSlotTypeScript && snapshot.scriptBodyEnabled) {
        return program_bits(snapshot.scriptBody.data(),
                            program_count(snapshot.scriptBodyCount, snapshot.scriptBody.size()));
    }
    if (slotType == kSlotTypeDirector && snapshot.directorBodyEnabled) {
        return program_bits(snapshot.directorBody.data(),
                            program_count(snapshot.directorBodyCount, snapshot.directorBody.size()));
    }
    return 0;
}

/** Writes one slot's auth body. */
bool write_auth_body(bits::Writer& writer,
                     const Snapshot& snapshot,
                     std::uint8_t slotType,
                     bool carriesPlayerKey) noexcept {
    const std::size_t start = writer.bit_count();
    const std::size_t expected = auth_body_bits(snapshot, slotType, carriesPlayerKey);
    bool encoded = true;
    if (slotType == kSlotTypeParticipation && carriesPlayerKey) {
        encoded = write_participation(writer, snapshot);
    } else if (slotType == kSlotTypeLifetime) {
        encoded = write_lifetime(writer, snapshot);
    } else if (slotType == kSlotTypeConfiguration) {
        // Both optional arrays absent and the terminal tag clear is the constructed state.
        encoded = writer.write(0, kPresenceWidth) && writer.write(0, kPresenceWidth)
                  && writer.write(0, kPresenceWidth) && writer.write(0, 32);
    } else if (slotType == kSlotTypePackage) {
        // 7 absent top-level fields keep the package-owned configuration.
        encoded = pad_bits(writer, kPackageBits);
    } else if (slotType == kSlotTypeQueues) {
        encoded = writer.write(0, 7) && writer.write(0, 5);
    } else if (slotType == kSlotTypeSpawnKeys) {
        encoded = write_spawn_keys(writer);
    } else if (slotType == kSlotTypeSquad && snapshot.squadPlaceEnabled) {
        // Minimal 0x80807ec9 body (M1 first pass): every optional absent so the client instantiates
        // the squad from its own authored placement (position and combatant carried by the content),
        // not from a body-supplied one. 18 absent optionals, the 2-bit and 3-bit fixed fields carry
        // squadPlaceValue, then one absent optional. Consistent with the client schema, so no desync;
        // the question this answers is whether a seeded squad slot with a valid body instantiates.
        for (std::size_t index = 0; encoded && index < 18; ++index) {
            encoded = writer.write(0, kPresenceWidth);
        }
        encoded = encoded && writer.write(snapshot.squadPlaceValue & 0x3U, 2)
                  && writer.write((snapshot.squadPlaceValue >> 2) & 0x7U, 3)
                  && writer.write(0, kPresenceWidth);
    } else if (slotType == kSlotTypeScript && snapshot.scriptBodyEnabled) {
        encoded = write_program(writer,
                                snapshot.scriptBody.data(),
                                program_count(snapshot.scriptBodyCount, snapshot.scriptBody.size()));
    } else if (slotType == kSlotTypeDirector && snapshot.directorBodyEnabled) {
        encoded =
            write_program(writer,
                          snapshot.directorBody.data(),
                          program_count(snapshot.directorBodyCount, snapshot.directorBody.size()));
    }
    return encoded && writer.bit_count() == start + expected;
}

} // namespace sunrise::middleware::bap::activity_message::sensor_auth_update
