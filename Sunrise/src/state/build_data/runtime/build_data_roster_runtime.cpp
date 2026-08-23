#include "../runtime.h"
#include "../scenarios/scenario_catalog.h"

namespace sunrise::state::build_data {

/** Copies one roster group by the table index a destination row carries. */
bool find_roster_group(std::size_t index, scenarios::RosterGroup& group) noexcept {
    group = {};
    return scenario_layouts_ready() && scenarios::group(index, group);
}

/** Copies the first roster group whose registry key matches, scanning the whole table. */
bool find_roster_group_by_key(std::uint32_t registryKey, scenarios::RosterGroup& group) noexcept {
    group = {};
    if (registryKey == 0 || !scenario_layouts_ready()) {
        return false;
    }
    const std::size_t total = scenarios::group_count();
    for (std::size_t index = 0; index < total; ++index) {
        scenarios::RosterGroup candidate{};
        if (scenarios::group(index, candidate) && candidate.registryKey == registryKey) {
            group = candidate;
            return true;
        }
    }
    return false;
}

} // namespace sunrise::state::build_data
