#pragma once

#include <cstddef>

namespace sunrise::client::hooks::spawn::encounter {

/**
 * Places a mission's authored squads at their own world transforms as the player reaches them.
 *
 * The mission content already says where each squad stands: a placed object carries a rotation
 * quaternion followed by a world position. Those rows are extracted offline into an authored table
 * so the placement is data, not code, and a content change means editing a text file.
 *
 * Proximity is the trigger, not a destination query. An authored row only fires when the player is
 * within range of the coordinates that row names, so a table can never place its squads on a map
 * whose geometry never puts the player there.
 */

/** Reads the authored tables. Safe to call again; a reload replaces what was held. */
[[nodiscard]] bool load() noexcept;

/** Drops every loaded row and forgets what was already placed. */
void clear() noexcept;

/**
 * Appends the player position to the authored table, as a row waiting for its combatant.
 * @return True when the row reached the file.
 */
[[nodiscard]] bool record_here() noexcept;

/** Rows loaded from the authored tables. */
[[nodiscard]] std::size_t row_count() noexcept;

/** Rows already placed this session. */
[[nodiscard]] std::size_t placed_count() noexcept;

/**
 * Places any authored row the player has come within range of.
 * Called from the same per-frame service as the manual spawner, so it inherits its thread.
 */
void service() noexcept;

} // namespace sunrise::client::hooks::spawn::encounter
