#include <bitset>
#include <cstddef>
#include <limits>
#include <string_view>

#include "../../../state/activity/defaults/activity_defaults_validation.h"
#include "../parser.h"

namespace sunrise::core::settings::parser {
namespace {

/** An unsigned hash field is one fixed 32-bit value. */
constexpr std::uint64_t kMaximumHash = (std::numeric_limits<std::uint32_t>::max)();

/** @return The nibble value of one hex digit, or -1 when the character is not hex. */
[[nodiscard]] int hex_nibble(char value) noexcept {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

/** Fields needed for one complete authored destination and numeric fallback row. */
enum class DestinationField : std::size_t {
    reason,
    previousActivityIndex,
    activityIndex,
    packageName,
    bubbleCount,
    statefulBubbleMask,
    initialSliceSet,
    spawnSetHash,
    count,
};

/**
 * Marks one destination field exactly once.
 * @param supplied Per-field tracker for repeats and completeness.
 * @param field Field named by the current JSON key.
 * @return False when the field was already present.
 */
[[nodiscard]] bool mark(std::bitset<static_cast<std::size_t>(DestinationField::count)>& supplied,
                        DestinationField field) noexcept {
    const std::size_t index = static_cast<std::size_t>(field);
    if (supplied.test(index)) {
        return false;
    }
    supplied.set(index);
    return true;
}

/**
 * Copies one already-checked package name into the fixed destination storage.
 * @param value Nonempty package bytes that fit the 40-byte schema field.
 * @param selection Cleared destination receiving the bytes and the length.
 */
void assign_package_name(std::string_view value,
                         state::activity::destination::DestinationSelection& selection) noexcept {
    selection.packageNameLength = static_cast<std::uint8_t>(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        selection.packageName[index] = static_cast<std::int8_t>(value[index]);
    }
}

} // namespace

/** Parses the optional activity settings object on top of the State defaults. */
bool Parser::activity_settings(state::activity::defaults::ActivityDefaults& output) noexcept {
    if (!consume('{')) {
        return false;
    }
    bool hasDefaultDestination = false;
    bool hasArrivalOverrides = false;
    bool hasRosterKeyFromIdentity = false;
    bool hasRosterKeyOnAllSlots = false;
    bool hasSquadPlaceEnabled = false;
    bool hasSquadPlaceWidth = false;
    bool hasSquadPlaceValue = false;
    bool hasSquadPlaceKey = false;
    bool hasSquadPlaceIndex = false;
    bool hasSquadPlaceRegion = false;
    bool hasMonitorBodyEnabled = false;
    bool hasMonitorBodyKey = false;
    bool hasMonitorBodySlotType = false;
    bool hasMonitorBodySlotIndex = false;
    bool hasMonitorBodyValue = false;
    bool hasSquadReferenceEnabled = false;
    bool hasSquadReferenceSweep = false;
    bool hasSquadReferenceOptional = false;
    bool hasSquadReferenceKey = false;
    bool hasSquadReferenceSlotType = false;
    bool hasSquadReferenceSlotIndex = false;
    bool hasCommandEmitEnabled = false;
    bool hasCommandBody = false;
    bool hasCommandSweepEnabled = false;
    bool hasCommandSweepValue = false;
    bool hasScriptBodyEnabled = false;
    bool hasScriptBody = false;
    bool hasDirectorBodyEnabled = false;
    bool hasDirectorBody = false;
    bool hasIncidentEmitEnabled = false;
    bool hasIncidentTarget = false;
    bool hasIncidentSweepEnabled = false;
    bool hasIncidentBlockSize = false;
    bool hasIncidentReplayEnabled = false;
    bool hasIncidentBody = false;
    if (consume('}')) {
        return true;
    }
    for (;;) {
        std::string_view key;
        if (!string(key) || !consume(':')) {
            return false;
        }
        if (key == "default_destination") {
            if (hasDefaultDestination || !default_destination(output.defaultDestination)) {
                return false;
            }
            hasDefaultDestination = true;
        } else if (key == "arrival_overrides") {
            if (hasArrivalOverrides || !arrival_overrides(output)) {
                return false;
            }
            hasArrivalOverrides = true;
        } else if (key == "roster_key_from_identity") {
            if (hasRosterKeyFromIdentity || !boolean(output.rosterKeyFromIdentity)) {
                return false;
            }
            hasRosterKeyFromIdentity = true;
        } else if (key == "roster_key_on_all_slots") {
            if (hasRosterKeyOnAllSlots || !boolean(output.rosterKeyOnAllSlots)) {
                return false;
            }
            hasRosterKeyOnAllSlots = true;
        } else if (key == "squad_place_enabled") {
            if (hasSquadPlaceEnabled || !boolean(output.squadPlaceEnabled)) {
                return false;
            }
            hasSquadPlaceEnabled = true;
        } else if (key == "squad_place_width") {
            std::uint64_t width = 0;
            if (hasSquadPlaceWidth || !unsigned_integer(width) || width > 64) {
                return false;
            }
            output.squadPlaceWidth = static_cast<std::uint8_t>(width);
            hasSquadPlaceWidth = true;
        } else if (key == "squad_place_value") {
            std::uint64_t value = 0;
            if (hasSquadPlaceValue || !unsigned_integer(value)) {
                return false;
            }
            output.squadPlaceValue = value;
            hasSquadPlaceValue = true;
        } else if (key == "monitor_body_enabled") {
            if (hasMonitorBodyEnabled || !boolean(output.monitorBodyEnabled)) {
                return false;
            }
            hasMonitorBodyEnabled = true;
        } else if (key == "monitor_body_key") {
            std::uint64_t value = 0;
            if (hasMonitorBodyKey || !unsigned_integer(value) || value > 0xFFFFFFFFULL) {
                return false;
            }
            output.monitorBodyKey = static_cast<std::uint32_t>(value);
            hasMonitorBodyKey = true;
        } else if (key == "monitor_body_slot_type") {
            std::uint64_t value = 0;
            if (hasMonitorBodySlotType || !unsigned_integer(value) || value > 0x7FULL) {
                return false;
            }
            output.monitorBodySlotType = static_cast<std::uint8_t>(value);
            hasMonitorBodySlotType = true;
        } else if (key == "monitor_body_slot_index") {
            std::uint64_t value = 0;
            if (hasMonitorBodySlotIndex || !unsigned_integer(value) || value > 0xFFFFULL) {
                return false;
            }
            output.monitorBodySlotIndex = static_cast<std::uint16_t>(value);
            hasMonitorBodySlotIndex = true;
        } else if (key == "monitor_body_value") {
            std::uint64_t value = 0;
            if (hasMonitorBodyValue || !unsigned_integer(value) || value > 0xFFFFFFFFULL) {
                return false;
            }
            output.monitorBodyValue = static_cast<std::uint32_t>(value);
            hasMonitorBodyValue = true;
        } else if (key == "squad_reference_enabled") {
            if (hasSquadReferenceEnabled || !boolean(output.squadReferenceEnabled)) {
                return false;
            }
            hasSquadReferenceEnabled = true;
        } else if (key == "squad_reference_sweep") {
            if (hasSquadReferenceSweep || !boolean(output.squadReferenceSweep)) {
                return false;
            }
            hasSquadReferenceSweep = true;
        } else if (key == "squad_reference_optional") {
            std::uint64_t value = 0;
            if (hasSquadReferenceOptional || !unsigned_integer(value) || value > 18) {
                return false;
            }
            output.squadReferenceOptional = static_cast<std::uint8_t>(value);
            hasSquadReferenceOptional = true;
        } else if (key == "squad_reference_key") {
            std::uint64_t value = 0;
            if (hasSquadReferenceKey || !unsigned_integer(value) || value > 0xFFFFFFFFULL) {
                return false;
            }
            output.squadReferenceKey = static_cast<std::uint32_t>(value);
            hasSquadReferenceKey = true;
        } else if (key == "squad_reference_slot_type") {
            std::uint64_t value = 0;
            if (hasSquadReferenceSlotType || !unsigned_integer(value) || value > 0x7FULL) {
                return false;
            }
            output.squadReferenceSlotType = static_cast<std::uint8_t>(value);
            hasSquadReferenceSlotType = true;
        } else if (key == "squad_reference_slot_index") {
            std::uint64_t value = 0;
            if (hasSquadReferenceSlotIndex || !unsigned_integer(value) || value > 0xFFFFULL) {
                return false;
            }
            output.squadReferenceSlotIndex = static_cast<std::uint16_t>(value);
            hasSquadReferenceSlotIndex = true;
        } else if (key == "squad_place_key") {
            std::uint64_t key32 = 0;
            if (hasSquadPlaceKey || !unsigned_integer(key32) || key32 > 0xFFFFFFFFULL) {
                return false;
            }
            output.squadPlaceKey = static_cast<std::uint32_t>(key32);
            hasSquadPlaceKey = true;
        } else if (key == "squad_place_index") {
            std::uint64_t index = 0;
            if (hasSquadPlaceIndex || !unsigned_integer(index) || index > 0xFFFFULL) {
                return false;
            }
            output.squadPlaceIndex = static_cast<std::uint16_t>(index);
            hasSquadPlaceIndex = true;
        } else if (key == "squad_place_region") {
            std::int64_t region = 0;
            if (hasSquadPlaceRegion || !signed_integer(region)
                || region < (std::numeric_limits<std::int32_t>::min)()
                || region > (std::numeric_limits<std::int32_t>::max)()) {
                return false;
            }
            output.squadPlaceRegion = static_cast<std::int32_t>(region);
            hasSquadPlaceRegion = true;
        } else if (key == "command_emit_enabled") {
            if (hasCommandEmitEnabled || !boolean(output.commandEmitEnabled)) {
                return false;
            }
            hasCommandEmitEnabled = true;
        } else if (key == "command_body") {
            if (hasCommandBody || !bit_program(output.commandBody, output.commandBodyCount)) {
                return false;
            }
            hasCommandBody = true;
        } else if (key == "command_sweep_enabled") {
            if (hasCommandSweepEnabled || !boolean(output.commandSweepEnabled)) {
                return false;
            }
            hasCommandSweepEnabled = true;
        } else if (key == "command_sweep_value") {
            std::uint64_t value = 0;
            if (hasCommandSweepValue || !unsigned_integer(value)) {
                return false;
            }
            output.commandSweepValue = value;
            hasCommandSweepValue = true;
        } else if (key == "script_body_enabled") {
            if (hasScriptBodyEnabled || !boolean(output.scriptBodyEnabled)) {
                return false;
            }
            hasScriptBodyEnabled = true;
        } else if (key == "script_body") {
            if (hasScriptBody || !bit_program(output.scriptBody, output.scriptBodyCount)) {
                return false;
            }
            hasScriptBody = true;
        } else if (key == "director_body_enabled") {
            if (hasDirectorBodyEnabled || !boolean(output.directorBodyEnabled)) {
                return false;
            }
            hasDirectorBodyEnabled = true;
        } else if (key == "director_body") {
            if (hasDirectorBody || !bit_program(output.directorBody, output.directorBodyCount)) {
                return false;
            }
            hasDirectorBody = true;
        } else if (key == "incident_emit_enabled") {
            if (hasIncidentEmitEnabled || !boolean(output.incidentEmitEnabled)) {
                return false;
            }
            hasIncidentEmitEnabled = true;
        } else if (key == "incident_target") {
            std::uint64_t value = 0;
            if (hasIncidentTarget || !unsigned_integer(value) || value > 0xFFFFFFFFULL) {
                return false;
            }
            output.incidentTarget = static_cast<std::uint32_t>(value);
            hasIncidentTarget = true;
        } else if (key == "incident_sweep_enabled") {
            if (hasIncidentSweepEnabled || !boolean(output.incidentSweepEnabled)) {
                return false;
            }
            hasIncidentSweepEnabled = true;
        } else if (key == "incident_block_size") {
            std::uint64_t value = 0;
            if (hasIncidentBlockSize || !unsigned_integer(value) || value == 0
                || value > 0xFFFFFFFFULL) {
                return false;
            }
            output.incidentBlockSize = static_cast<std::uint32_t>(value);
            hasIncidentBlockSize = true;
        } else if (key == "incident_replay_enabled") {
            if (hasIncidentReplayEnabled || !boolean(output.incidentReplayEnabled)) {
                return false;
            }
            hasIncidentReplayEnabled = true;
        } else if (key == "incident_body") {
            std::string_view hex;
            if (hasIncidentBody || !string(hex) || hex.size() % 2 != 0
                || hex.size() / 2 > output.incidentBody.size()) {
                return false;
            }
            for (std::size_t index = 0; index < hex.size(); index += 2) {
                const int high = hex_nibble(hex[index]);
                const int low = hex_nibble(hex[index + 1]);
                if (high < 0 || low < 0) {
                    return false;
                }
                output.incidentBody[index / 2] =
                    static_cast<std::byte>((high << 4) | low);
            }
            output.incidentBodyLength = static_cast<std::uint16_t>(hex.size() / 2);
            hasIncidentBody = true;
        } else if (!skip_value(0)) {
            return false;
        }
        if (consume('}')) {
            return true;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

/** Parses one local destination and its small numeric launch policy. */
bool Parser::default_destination(state::activity::defaults::DefaultDestination& output) noexcept {
    if (!consume('{')) {
        return false;
    }
    std::bitset<static_cast<std::size_t>(DestinationField::count)> supplied;
    state::activity::defaults::DefaultDestination candidate{};
    if (consume('}')) {
        return false;
    }
    for (;;) {
        std::string_view key;
        if (!string(key) || !consume(':')) {
            return false;
        }
        if (key == "reason") {
            std::int64_t value = 0;
            if (!mark(supplied, DestinationField::reason) || !signed_integer(value)
                || value < state::activity::destination::kMinimumReason
                || value > state::activity::destination::kMaximumReason) {
                return false;
            }
            candidate.selection.reason = static_cast<std::int8_t>(value);
        } else if (key == "previous_activity_index") {
            std::int64_t value = 0;
            if (!mark(supplied, DestinationField::previousActivityIndex) || !signed_integer(value)
                || value < state::activity::destination::kAbsentActivityIndex
                || value > state::activity::destination::kMaximumActivityIndex) {
                return false;
            }
            candidate.selection.previousActivityIndex = static_cast<std::int16_t>(value);
        } else if (key == "activity_index") {
            std::int64_t value = 0;
            if (!mark(supplied, DestinationField::activityIndex) || !signed_integer(value)
                || value < 0 || value > state::activity::destination::kMaximumActivityIndex) {
                return false;
            }
            candidate.selection.activityIndex = static_cast<std::int16_t>(value);
        } else if (key == "package_name") {
            std::string_view value;
            if (!mark(supplied, DestinationField::packageName) || !string(value) || value.empty()
                || value.size() > state::activity::destination::kPackageNameCapacity) {
                return false;
            }
            assign_package_name(value, candidate.selection);
        } else if (key == "bubble_count") {
            std::uint64_t value = 0;
            if (!mark(supplied, DestinationField::bubbleCount) || !unsigned_integer(value)
                || value < state::activity::defaults::kMinimumBubbleCount
                || value > state::activity::defaults::kBubbleCapacity) {
                return false;
            }
            candidate.fallback.bubbleCount = static_cast<std::uint8_t>(value);
        } else if (key == "stateful_bubble_mask") {
            if (!mark(supplied, DestinationField::statefulBubbleMask)
                || !unsigned_value(candidate.fallback.statefulBubbleMask)) {
                return false;
            }
        } else if (key == "initial_slice_set") {
            std::uint64_t value = 0;
            if (!mark(supplied, DestinationField::initialSliceSet) || !unsigned_integer(value)
                || value > state::activity::defaults::kMaximumInitialSliceSet) {
                return false;
            }
            candidate.fallback.initialSliceSet = static_cast<std::uint16_t>(value);
        } else if (key == "spawn_set_hash") {
            std::uint64_t value = 0;
            if (!mark(supplied, DestinationField::spawnSetHash) || !unsigned_value(value)
                || value > kMaximumHash) {
                return false;
            }
            candidate.fallback.spawnSetHash = static_cast<std::uint32_t>(value);
        } else if (!skip_value(0)) {
            return false;
        }
        if (consume('}')) {
            // A complete row stops the package name and the numeric layout policy from mixing.
            if (!supplied.all() || !state::activity::defaults::valid(candidate)) {
                return false;
            }
            output = candidate;
            return true;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

/** Fills one bit-program from [width, value] pairs into fixed step storage. */
bool Parser::bit_program(std::array<state::activity::defaults::CommandBodyStep,
                                    state::activity::defaults::kCommandBodyCapacity>& steps,
                         std::uint8_t& count) noexcept {
    count = 0;
    if (!consume('[')) {
        return false;
    }
    if (consume(']')) {
        return true;
    }
    for (;;) {
        std::uint64_t width = 0;
        std::uint64_t value = 0;
        if (count >= steps.size() || !consume('[') || !unsigned_integer(width) || !consume(',')
            || !unsigned_integer(value) || !consume(']') || width < 1 || width > 64) {
            return false;
        }
        // A value with bits above its field would silently truncate on the wire, so a program that
        // does not fit its declared widths is rejected rather than mis-encoded.
        if (width < 64 && value >= (static_cast<std::uint64_t>(1) << width)) {
            return false;
        }
        state::activity::defaults::CommandBodyStep& step = steps[count++];
        step.width = static_cast<std::uint8_t>(width);
        step.value = value;
        if (consume(']')) {
            return true;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

} // namespace sunrise::core::settings::parser
