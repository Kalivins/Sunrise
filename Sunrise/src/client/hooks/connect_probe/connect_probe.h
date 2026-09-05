#pragma once

namespace sunrise::client::hooks::connect_probe {

/** Attaches the connect-path entry probe. @return True when at least one detour attaches. */
[[nodiscard]] bool install() noexcept;

/** Detaches the connect-path entry probe. */
void uninstall() noexcept;

} // namespace sunrise::client::hooks::connect_probe
