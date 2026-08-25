#include <array>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../../middleware/content/packages/tables/roster_intersection.h"
#include "../../../middleware/content/packages/tables/scenario_reader.h"
#include "../../../middleware/content/packages/tables/slot_descriptor_reader.h"
#include "internal.h"

namespace sunrise::client::content::scenarios {
namespace {

namespace tables = middleware::content::packages::tables;

/** How many hops the chain from a handle to a descriptor blob may take. */
constexpr std::size_t kChainDepthLimit = 8;

/** Squad slot type, and how many squad slots of the full group get an auth body on the M1 first
 *  pass. Capped so a seeded squad-parent instantiates a handful of squads to prove the mechanism,
 *  not every squad the mission declares at once. */
constexpr std::uint8_t kSquadSlotType = 1;
constexpr unsigned kSquadAuthLimit = 32;
/** Monitor slot type, and how many of them get an auth body. The group carries five, few enough to
 *  publish whole; the encoder writes the type-30 schema the slot descriptor names. */
constexpr std::uint8_t kMonitorSlotType = 30;
constexpr unsigned kMonitorAuthLimit = 5;

/**
 * SCOPED SENSOR PROBE (diagnostic). Chosen's sensor/squad objects (type-30 slots) that the roster
 * whitelist does not admit on its own. Admitting them by exact registry key keeps the extraction
 * cheap -- a global type-30 widen resolves ~1806 objects and hangs the cache rebuild -- while
 * getting Chosen's sensors into the published roster, to test whether a mounted sensor births a
 * client sense_update. Keys measured from last_city_liberation's scenario walk. To be removed.
 */
constexpr std::array<std::uint32_t, 18> kScopedSensorKeys = {
    0x030d2bcaU, 0x0c416ebfU, 0x169e2d77U, 0x2e65274eU, 0x8ad2b200U, 0x8ad2b203U,
    0x8c040d5dU, 0xa3f4edb4U, 0xb2660a00U, 0xb7f41096U, 0xbca1e578U, 0xc8e4ce0cU,
    0xddd553b3U, 0xe3797278U, 0xe8aef4cdU, 0xeb3c061aU, 0xef4eaa1eU, 0xf3a33d80U};

/** True when a registry key is one of the scoped sensor objects to admit past the whitelist. */
[[nodiscard]] bool is_scoped_sensor(std::uint32_t registryKey) noexcept {
    for (const std::uint32_t key : kScopedSensorKeys) {
        if (key == registryKey) {
            return true;
        }
    }
    return false;
}

/**
 * SCOPED SQUAD PROBE (diagnostic). The parent objects that carry Chosen's squad slots (type 1) are
 * not whitelisted, so mission_reunion publishes no squad slot at all. Key 0xEF4EAA1E carries
 * squad_ikora / squad_cabal_dropoff_1 / squad_cabal_puncher (measured: 30 and 43 squad slots on its
 * two placements, key non-zero -- the object_key=0 seen before was the squad sub-instance, not this
 * parent). Admitting it by exact key publishes the squad slots against the object's REAL structure,
 * which the client can seed, where the earlier one-slot synthetic injection could not. To be removed.
 */
constexpr std::array<std::uint32_t, 1> kScopedSquadKeys = {0xef4eaa1eU};

/**
 * The one encounter whose group may be published short. A registry key is shared by every object of
 * its encounter, so lifting the rule for the whole scoped list admitted far more groups than the
 * table holds; overflow aborts the scenario walk and the destination then publishes nothing, which
 * is what left the client waiting on a world that never came. One key keeps the addition small.
 */
constexpr std::uint32_t kShortGroupKey = 0xe3797278U;

/** True when a registry key is one of the scoped squad-parent objects to admit past the whitelist. */
[[nodiscard]] bool is_scoped_squad(std::uint32_t registryKey) noexcept {
    for (const std::uint32_t key : kScopedSquadKeys) {
        if (key == registryKey) {
            return true;
        }
    }
    return false;
}

/**
 * Records one descriptor as a slot of the object being resolved.
 * @param context Roster storage.
 * @param descriptor Descriptor read from a placed-object blob.
 * @return Always true, because a descriptor this pass cannot use is ordinary.
 */
bool collect_slot(void* context, const tables::SlotDescriptor& descriptor) noexcept {
    record_slot(*static_cast<RosterStorage*>(context), descriptor);
    return true;
}

/**
 * Follows one placed handle to its descriptor blob and records what it declares.
 * @param source Package directory and borrowed block keys.
 * @param scratch Lock-owned block storage.
 * @param storage Working storage for this pass.
 * @param handle Tag from a placed object's per-bubble sub-block.
 * @param registryKey Registry key the descriptors must name.
 */
void follow_handle(const reader::Source& source,
                   reader::Scratch& scratch,
                   RosterStorage& storage,
                   std::uint32_t handle,
                   std::uint32_t registryKey) noexcept {
    std::uint32_t tag = handle;
    ++storage.handleTotal;
    for (std::size_t depth = 0; depth < kChainDepthLimit; ++depth) {
        std::uint32_t classId = 0;
        ++storage.reads;
        if (!reader::read_tag(source, scratch, tag, storage.chain, classId)) {
            ++storage.handleFails;
            return;
        }
        if (classId == tables::kPlacedObjectClass) {
            (void)tables::visit_slot_descriptors(
                storage.chain, tag, registryKey, &collect_slot, &storage);
            return;
        }
        std::uint32_t next = 0;
        if (!tables::next_descriptor_tag(storage.chain, classId, next)) {
            return;
        }
        tag = next;
    }
}

/**
 * Collects every descriptor one group object declares, over all of its per-bubble sub-blocks.
 * Every leaf is followed: one leaf is one slot, so stopping early would drop slots rather than
 * merely leave a slot type unresolved.
 * @param source Package directory and borrowed block keys.
 * @param scratch Lock-owned block storage.
 * @param storage Working storage receiving the descriptors.
 * @param objectBlob Whole placed-object bytes.
 * @param registryKey Registry key the descriptors must name.
 */
void collect_descriptors(const reader::Source& source,
                         reader::Scratch& scratch,
                         RosterStorage& storage,
                         std::span<const std::byte> objectBlob,
                         std::uint32_t registryKey) noexcept {
    tables::Array bubbles{};
    if (!tables::object_bubbles(objectBlob, bubbles)) {
        return;
    }
    for (std::uint64_t index = 0; index < bubbles.count; ++index) {
        tables::ObjectBubble bubble{};
        if (!tables::object_bubble_at(objectBlob, bubbles, index, bubble)) {
            return;
        }
        for (std::uint64_t slot = 0; slot < bubble.handleCount; ++slot) {
            std::uint32_t handle = 0;
            if (!tables::object_placed_handle_at(objectBlob, bubble, slot, handle)) {
                return;
            }
            follow_handle(source, scratch, storage, handle, registryKey);
        }
    }
}

/** @param storage Working storage. @param tag Object tag. @return Its memo slot, or capacity. */
[[nodiscard]] std::size_t memo_slot(const RosterStorage& storage, std::uint32_t tag) noexcept {
    std::size_t probe = tag % kObjectMemoCapacity;
    for (std::size_t step = 0; step < kObjectMemoCapacity; ++step) {
        if (storage.memo[probe].tag == 0 || storage.memo[probe].tag == tag) {
            return probe;
        }
        probe = (probe + 1) % kObjectMemoCapacity;
    }
    return kObjectMemoCapacity;
}

} // namespace

/**
 * Finds the roster group of one placed object, reading it only the first time it is seen.
 * @param source Package directory and borrowed block keys.
 * @param scratch Lock-owned block storage.
 * @param storage Working storage for this pass.
 * @param objectTag Tag from an object registry.
 * @param group Receives the roster group index, or the not-a-group sentinel.
 * @return True when the object was read or was already known.
 */
bool resolve_object(const reader::Source& source,
                    reader::Scratch& scratch,
                    RosterStorage& storage,
                    std::uint32_t objectTag,
                    std::uint16_t& group) noexcept {
    group = kNotARosterGroup;
    const std::size_t slot = memo_slot(storage, objectTag);
    if (slot == kObjectMemoCapacity) {
        return false;
    }
    if (storage.memo[slot].tag == objectTag) {
        group = storage.memo[slot].group;
        return true;
    }
    storage.memo[slot].tag = objectTag;
    storage.memo[slot].group = kNotARosterGroup;
    ++storage.reads;
    if (!reader::read_tag(source, scratch, objectTag, storage.object)) {
        return true;
    }

    // WITNESS (diagnostic): locate the objects that carry a squad slot (type 1) or a sensor slot
    // (type 30), and report each one's runtime object_key plus whether the whitelist already admits
    // it. squad.place needs a type-1 slot published against an object the client can SEED; the seed
    // key is the carrying object's registry key. This settles whether any type-1-bearing object has
    // a non-zero, admitted key (seedable today) or every one hits the placement key=0 wall (needs
    // the registry-element key instead). Removed after.
    {
        std::uint32_t witnessKey = 0;
        static_cast<void>(tables::object_key(storage.object, witnessKey));
        tables::Array witnessSlots{};
        unsigned squadSlots = 0;
        unsigned sensorSlots = 0;
        if (tables::object_slots(storage.object, witnessSlots)) {
            for (std::uint64_t s = 0; s < witnessSlots.count; ++s) {
                tables::Slot descriptor{};
                if (!tables::object_slot_at(storage.object, witnessSlots, s, descriptor)) {
                    continue;
                }
                if (descriptor.type == 1) {
                    ++squadSlots;
                } else if (descriptor.type == 30) {
                    ++sensorSlots;
                }
            }
        }
        if (squadSlots != 0 || sensorSlots != 0) {
            std::array<char, core::log::kLineCapacity> witnessLine{};
            const int witnessLen = std::snprintf(
                witnessLine.data(),
                witnessLine.size(),
                "ev=build_data stage=squad_key tag=0x%08X key=0x%08X squad=%u sensor=%u admit=%d",
                objectTag,
                witnessKey,
                squadSlots,
                sensorSlots,
                (tables::carries_roster_slot(storage.object) || is_scoped_sensor(witnessKey)
                 || is_scoped_squad(witnessKey))
                    ? 1
                    : 0);
            if (witnessLen > 0) {
                core::log::write(core::log::Channel::state,
                                 core::log::Level::warn,
                                 {witnessLine.data(), static_cast<std::size_t>(witnessLen)});
            }
        }
    }

    layouts::RosterGroup candidate{};
    tables::Array declared{};
    if (!tables::object_key(storage.object, candidate.registryKey) || candidate.registryKey == 0
        || (!tables::carries_roster_slot(storage.object)
            && !is_scoped_sensor(candidate.registryKey)
            && !is_scoped_squad(candidate.registryKey))
        || !tables::object_slots(storage.object, declared) || declared.count == 0
        || declared.count > layouts::kRosterSlotCapacity) {
        return true;
    }
    storage.slotCount = 0;
    storage.slotsOverflowed = false;
    storage.handleTotal = 0;
    storage.handleFails = 0;
    collect_descriptors(source, scratch, storage, storage.object, candidate.registryKey);

    // DIRECTOR M0 WITNESS (diagnostic). The make-or-break for building the full group from the
    // declaration is whether a static descriptor's slotIndex equals its position in the object's
    // declared slot array (object_slots). If it does, the ~125 script-placed slots that have no
    // descriptor simply occupy the declaration positions no descriptor covers, and the full group is
    // publishable as declaration order. Compare the descriptors we DID collect against the
    // declaration at their own slotIndex, and count the declaration positions no descriptor covers.
    if (is_scoped_squad(candidate.registryKey)) {
        std::array<bool, layouts::kRosterSlotCapacity> covered{};
        unsigned inRange = 0;
        unsigned typeMatch = 0;
        std::uint16_t idxMin = 0xFFFFU;
        std::uint16_t idxMax = 0;
        for (std::size_t s = 0; s < storage.slotCount; ++s) {
            const std::uint16_t di = storage.slots[s].index;
            idxMin = di < idxMin ? di : idxMin;
            idxMax = di > idxMax ? di : idxMax;
            if (di < declared.count) {
                ++inRange;
                covered[di] = true;
                tables::Slot decl{};
                if (tables::object_slot_at(storage.object, declared, di, decl)
                    && static_cast<std::uint8_t>(decl.type) == storage.slots[s].type) {
                    ++typeMatch;
                }
            }
        }
        unsigned gaps = 0;
        for (std::uint64_t d = 0; d < declared.count; ++d) {
            if (!covered[d]) {
                ++gaps;
            }
        }
        std::array<char, core::log::kLineCapacity> idxLine{};
        const int idxLen = std::snprintf(
            idxLine.data(),
            idxLine.size(),
            "ev=build_data stage=squad_index key=0x%08X declared=%llu collected=%u inRange=%u "
            "typeMatch=%u gaps=%u idxMin=%u idxMax=%u",
            candidate.registryKey,
            static_cast<unsigned long long>(declared.count),
            static_cast<unsigned>(storage.slotCount),
            inRange,
            typeMatch,
            gaps,
            static_cast<unsigned>(idxMin),
            static_cast<unsigned>(idxMax));
        if (idxLen > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::warn,
                             {idxLine.data(), static_cast<std::size_t>(idxLen)});
        }
    }

    bool built = false;
    if (is_scoped_squad(candidate.registryKey)) {
        // DIRECTOR M0: build the FULL group from the object's declaration (object_slots), not from the
        // static descriptors. The squad_index witness confirmed a descriptor's slotIndex is its
        // declaration position (typeMatch == inRange, idx range 0..declared-1), so the ~97 script-placed
        // slots that carry no static descriptor occupy exactly the declaration positions no descriptor
        // covers. Publishing every declared slot keyed by its position seeds the whole object, which is
        // what stops the bubble from holding. Seed-only (flags 0): auth bodies that actually instantiate
        // a squad come in a later step; here the goal is only that the parent seeds without a hold.
        built = declared.count > 0 && declared.count <= layouts::kRosterSlotCapacity;
        unsigned squadBodies = 0;
        unsigned monitorBodies = 0;
        for (std::uint64_t index = 0; built && index < declared.count; ++index) {
            tables::Slot declaredSlot{};
            if (!tables::object_slot_at(storage.object, declared, index, declaredSlot)
                || declaredSlot.type == 0 || declaredSlot.type > layouts::kMaximumSlotType) {
                built = false;
                break;
            }
            candidate.slotTypes[index] = static_cast<std::uint8_t>(declaredSlot.type);
            // Give the auth flag to the slots this encoder can write a body for, so the snapshot
            // carries authority rather than a seed. Squads ask the client to instantiate them;
            // monitors carry the type-30 body their slot descriptor names. Both are capped, so a
            // first pass authors a handful rather than every slot the mission declares.
            std::uint8_t flags = 0;
            if (declaredSlot.type == kSquadSlotType && squadBodies < kSquadAuthLimit) {
                flags = layouts::kSlotAuthFlag;
                ++squadBodies;
            } else if (declaredSlot.type == kMonitorSlotType && monitorBodies < kMonitorAuthLimit) {
                flags = layouts::kSlotAuthFlag;
                ++monitorBodies;
            }
            candidate.slotFlags[index] = flags;
            candidate.slotIndices[index] = static_cast<std::uint16_t>(index);
        }
        if (built) {
            candidate.slotCount = static_cast<std::uint16_t>(declared.count);
        }
    } else {
        // Short is allowed only for the scoped encounter keys: they are the groups whose spawn
        // rules never reach the wire, and lifting the rule for everything empties the roster.
        const bool allowShort = core::settings::get().server.activation.rosterShortGroups
                                && candidate.registryKey == kShortGroupKey;
        built = fill_slots(storage, declared.count, allowShort, candidate);
    }
    if (!built) {
        // The client registers a record per slot the object declares and refuses its whole apply
        // while any record in the current bubble is unseeded, so a group missing one descriptor is
        // dropped rather than published short.
        // WITNESS (diagnostic): whether the scoped squad-parent group survives extraction. A drop
        // here (its slot descriptors do not all resolve from this scenario walk) means it never
        // reaches the published table, so the snapshot injection finds nothing to reference.
        if (is_scoped_squad(candidate.registryKey)) {
            std::array<char, core::log::kLineCapacity> dropLine{};
            const int dropLen = std::snprintf(
                dropLine.data(),
                dropLine.size(),
                "ev=build_data stage=squad_resolve key=0x%08X result=drop declared=%llu collected=%u "
                "handles=%u handleFails=%u",
                candidate.registryKey,
                static_cast<unsigned long long>(declared.count),
                static_cast<unsigned>(storage.slotCount),
                static_cast<unsigned>(storage.handleTotal),
                static_cast<unsigned>(storage.handleFails));
            if (dropLen > 0) {
                core::log::write(core::log::Channel::state,
                                 core::log::Level::warn,
                                 {dropLine.data(), static_cast<std::size_t>(dropLen)});
            }
        }
        ++storage.unresolvedGroups;
        return true;
    }
    if (is_scoped_squad(candidate.registryKey)) {
        std::array<char, core::log::kLineCapacity> okLine{};
        const int okLen = std::snprintf(
            okLine.data(),
            okLine.size(),
            "ev=build_data stage=squad_resolve key=0x%08X result=ok declared=%llu slots=%u "
            "handles=%u handleFails=%u",
            candidate.registryKey,
            static_cast<unsigned long long>(declared.count),
            static_cast<unsigned>(candidate.slotCount),
            static_cast<unsigned>(storage.handleTotal),
            static_cast<unsigned>(storage.handleFails));
        if (okLen > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::warn,
                             {okLine.data(), static_cast<std::size_t>(okLen)});
        }
    }
    candidate.objectTag = objectTag;
    // One key may carry different layouts in different activities, so only exact layouts reuse.
    for (std::size_t index = 0; index < storage.groupCount; ++index) {
        if (same_group_layout(storage.groups[index], candidate)) {
            storage.memo[slot].group = static_cast<std::uint16_t>(index);
            group = storage.memo[slot].group;
            return true;
        }
    }
    if (storage.groupCount == layouts::kRosterGroupCapacity) {
        return false;
    }
    storage.groups[storage.groupCount] = candidate;
    storage.memo[slot].group = static_cast<std::uint16_t>(storage.groupCount);
    group = storage.memo[slot].group;
    ++storage.groupCount;
    return true;
}

} // namespace sunrise::client::content::scenarios
