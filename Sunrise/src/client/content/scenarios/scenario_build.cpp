#include "scenario_build.h"

#include <array>
#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

#include "../../../core/logging/log.h"
#include "../../../middleware/content/packages/tables/scenario_walk.h"
#include "../../../state/build_data/runtime.h"
#include "internal.h"

namespace sunrise::client::content::scenarios {
namespace {

namespace packages = middleware::content::packages;

/**
 * Reports the pass so a boot that falls back to authored defaults says which step lost the rows.
 * Each count is separate on purpose: a sweep that finds tags, a name match that finds none, and a
 * blob read that drops every row all end with no domain and need different fixes.
 * @param storage Pass storage holding every count.
 * @param kept Rows whose blob read and parsed.
 * @param rostered Rows that published at least one roster group.
 * @param result Outcome text for the log line.
 */
void report(const Storage& storage,
            std::size_t kept,
            std::size_t rostered,
            const char* result) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written =
        std::snprintf(line.data(),
                      line.size(),
                      "ev=build_data stage=scenarios tags=%zu named=%zu live=%zu kept=%zu "
                      "groups=%zu dropped=%zu rostered=%zu result=%s",
                      storage.liveTagCount,
                      storage.rowCount,
                      storage.liveRowCount,
                      kept,
                      storage.roster.groupCount,
                      storage.roster.unresolvedGroups,
                      rostered,
                      result);
    if (written > 0) {
        core::log::write(core::log::Channel::state,
                         kept != 0 ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** DIAG ONLY: aggregates one scenario walk instead of printing every placement. */
struct DiagWalk {
    const packages::reader::Source* source{};
    packages::reader::Scratch* scratch{};
    std::array<std::vector<std::byte>, 3> slots{};
    std::array<std::uint32_t, 96> classes{};
    std::array<std::uint32_t, 96> counts{};
    std::size_t classCount{};
    std::uint32_t lastObjectClass{};
};

/** DIAG ONLY: supplies one nested blob to the walk, recording the object class it reads. */
bool diag_read(void* context,
               packages::tables::ReadSlot slot,
               std::uint32_t tag,
               std::span<const std::byte>& blob) noexcept {
    auto& diag = *static_cast<DiagWalk*>(context);
    const auto index = static_cast<std::size_t>(slot);
    if (index >= diag.slots.size()) {
        return false;
    }
    std::uint32_t classId = 0;
    if (!packages::reader::read_tag(*diag.source, *diag.scratch, tag, diag.slots[index], classId)) {
        return false;
    }
    blob = std::span<const std::byte>(diag.slots[index]);
    if (slot == packages::tables::ReadSlot::object) {
        diag.lastObjectClass = classId;
    }
    return true;
}

/** DIAG ONLY: reports one placement with every slot the object declares. */
void diag_report_slots(const packages::tables::Placement& placement) noexcept {
    packages::tables::Array slots{};
    const bool found = packages::tables::object_slots(placement.objectBytes, slots);
    std::array<char, core::log::kLineCapacity> line{};
    int written = std::snprintf(line.data(),
                                line.size(),
                                "ev=diag stage=placement bubble=0x%08X state=0x%08X object=0x%08X "
                                "key=0x%08X slots=%llu found=%u",
                                placement.bubbleHash,
                                placement.stateHash,
                                placement.objectTag,
                                placement.objectKey,
                                static_cast<unsigned long long>(placement.slotCount),
                                found ? 1U : 0U);
    if (written > 0) {
        core::log::write(core::log::Channel::state,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    if (!found) {
        return;
    }
    for (std::size_t index = 0; index < placement.slotCount; ++index) {
        packages::tables::Slot slot{};
        if (!packages::tables::object_slot_at(placement.objectBytes, slots, index, slot)) {
            break;
        }
        written =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=diag stage=slot object=0x%08X index=%zu type=0x%08X hash=0x%08X",
                          placement.objectTag,
                          index,
                          slot.type,
                          slot.nameHash);
        if (written > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
}

/** DIAG ONLY: counts one placement under the class of the object it placed. */
bool diag_placement(void* context, const packages::tables::Placement& placement) noexcept {
    auto& diag = *static_cast<DiagWalk*>(context);
    diag_report_slots(placement);
    for (std::size_t index = 0; index < diag.classCount; ++index) {
        if (diag.classes[index] == diag.lastObjectClass) {
            ++diag.counts[index];
            return true;
        }
    }
    if (diag.classCount < diag.classes.size()) {
        diag.classes[diag.classCount] = diag.lastObjectClass;
        diag.counts[diag.classCount] = 1;
        ++diag.classCount;
    }
    return true;
}

/** DIAG ONLY: walks one destination and reports what it places. */
void diag_walk(const packages::reader::Source& source,
               packages::reader::Scratch& scratch,
               const layouts::Definition& row) noexcept {
    static DiagWalk diag{};
    diag.classCount = 0;
    diag.lastObjectClass = 0;
    diag.source = &source;
    diag.scratch = &scratch;
    const std::string_view name(row.name.data(), row.nameLength);
    std::array<char, core::log::kLineCapacity> line{};
    std::vector<std::byte> blob{};
    if (!packages::reader::read_tag(source, scratch, row.tag, blob)) {
        const int failed = std::snprintf(line.data(),
                                         line.size(),
                                         "ev=diag stage=scenario_walk result=no_blob name=%.*s",
                                         static_cast<int>(name.size()),
                                         name.data());
        if (failed > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(failed)});
        }
        return;
    }
    packages::tables::WalkResult walk{};
    const bool ok =
        packages::tables::walk_scenario(blob, &diag_read, &diag, &diag_placement, &diag, walk);
    int written = std::snprintf(line.data(),
                                line.size(),
                                "ev=diag stage=scenario_walk result=%s name=%.*s bubbles=%llu "
                                "states=%llu entries=%llu registries=%llu placements=%llu "
                                "unresolved=%llu classes=%zu",
                                ok ? "ok" : "partial",
                                static_cast<int>(name.size()),
                                name.data(),
                                static_cast<unsigned long long>(walk.bubbles),
                                static_cast<unsigned long long>(walk.states),
                                static_cast<unsigned long long>(walk.entries),
                                static_cast<unsigned long long>(walk.registries),
                                static_cast<unsigned long long>(walk.placements),
                                static_cast<unsigned long long>(walk.unresolved),
                                diag.classCount);
    if (written > 0) {
        core::log::write(core::log::Channel::state,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    for (std::size_t index = 0; index < diag.classCount; ++index) {
        written = std::snprintf(line.data(),
                                line.size(),
                                "ev=diag stage=scenario_class name=%.*s class=0x%08X count=%u",
                                static_cast<int>(name.size()),
                                name.data(),
                                diag.classes[index],
                                diag.counts[index]);
        if (written > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
}

/** DIAG ONLY: destinations the walk reports on. */
constexpr std::string_view kDiagNames[] = {"pvp_wilderness_town_2", "pvp_bannerfall_2"};

/**
 * Walks the next batch of rosters and publishes the domain once the walk finishes.
 * @param source Package directory and borrowed block keys.
 * @param scratch Lock-owned block storage.
 * @param storage Pass storage holding the collected rows and the walk cursor.
 * @return True only when the whole domain is published.
 */
[[nodiscard]] bool walk_rosters(const packages::reader::Source& source,
                                packages::reader::Scratch& scratch,
                                Storage& storage) noexcept {
    const auto rows = std::span(storage.rows).first(storage.keptCount);
    if (!build_rosters(source, scratch, storage.roster, rows)) {
        return false;
    }
    std::size_t rostered = 0;
    for (const layouts::Definition& row : rows) {
        rostered += row.rosterGroupCount != 0 ? 1U : 0U;
    }
    const bool published = state::build_data::publish_scenario_layouts(
        rows, std::span(storage.roster.groups).first(storage.roster.groupCount));
    report(storage, storage.keptCount, rostered, published ? "ok" : "publish");
    // DIAG ONLY
    if (published) {
        for (const std::string_view wanted : kDiagNames) {
            for (const layouts::Definition& row : rows) {
                if (std::string_view(row.name.data(), row.nameLength) == wanted) {
                    diag_walk(source, scratch, row);
                }
            }
        }
    }
    storage.roster = {};
    return published;
}

} // namespace

/** Extracts every destination's bubble layout and roster from the installed packages, once. */
bool build(const packages::reader::Source& source, packages::reader::Scratch& scratch) noexcept {
    if (state::build_data::scenario_layouts_ready()) {
        return true;
    }
    static Storage storage{};
    if (!storage.collected) {
        const char* reason = nullptr;
        if (!collect_rows(source, storage, reason)) {
            report(storage, 0, 0, reason);
            return false;
        }
        storage.collected = true;
        report(storage, 0, 0, "collecting");
        return false;
    }
    if (!storage.compacted) {
        if (!resolve_pending(source, scratch, storage)) {
            return false;
        }
        compact_rows(storage);
        // An empty result is never a finished pass. Every blob read needs the block keys, and
        // those arrive during the boot, so a window that closes first reads nothing. Latching it
        // would publish a domain with no destinations for the whole run. Only the first empty
        // round reports, because the retry runs on every worker slice.
        if (storage.keptCount == 0) {
            if (storage.resolveRounds == 0) {
                report(storage, 0, 0, "empty");
            }
            rearm_resolve(storage);
            return false;
        }
        report(storage, storage.keptCount, 0, "collected");
        storage.compacted = true;
    }
    return walk_rosters(source, scratch, storage);
}

} // namespace sunrise::client::content::scenarios
