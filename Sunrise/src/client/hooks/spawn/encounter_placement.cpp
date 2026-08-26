#include "encounter_placement.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <vector>

#include "../../../core/filesystem/path.h"
#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../../state/build_data/entity_names/definition.h"
#include "../../../state/build_data/entity_names/entity_name_catalog.h"
#include "../teleport/runtime.h"
#include "spawn_runtime.h"

namespace sunrise::client::hooks::spawn::encounter {
namespace {

/** The authored tables live beside settings.json, in the Sunrise-owned folder. */
constexpr std::wstring_view kTableSuffix = L"\\encounter_placements\\mission_reunion.txt";
/** A table larger than this is refused rather than truncated into a half-read placement set. */
constexpr std::size_t kTableCapacity = 256 * 1024;
/** More rows than any single mission authors; the cap keeps storage bounded. */
constexpr std::size_t kRowCapacity = 512;
/** A combatant of this name is a row whose content named its enemy by hash, not by base name. */
constexpr std::string_view kUnresolvedCombatant = "?";
/** Metres from an authored position at which its squad is placed. */
constexpr float kPlacementRadius = 120.0F;

struct Row {
    std::array<char, 64> name{};
    std::array<char, 64> combatant{};
    std::array<float, 3> position{};
    std::array<float, 4> rotation{};
    bool placed{};
};

std::vector<Row> g_rows;
std::atomic<std::size_t> g_placed{0};
SRWLOCK g_lock = SRWLOCK_INIT;

void report(const char* format, ...) noexcept {
    std::array<char, 192> line{};
    va_list args;
    va_start(args, format);
    const int written = std::vsnprintf(line.data(), line.size(), format, args);
    va_end(args);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** @return Text with leading and trailing blanks removed. */
[[nodiscard]] std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    return text;
}

void copy_into(std::array<char, 64>& field, std::string_view text) noexcept {
    const std::size_t length = (std::min)(text.size(), field.size() - 1);
    std::memcpy(field.data(), text.data(), length);
    field[length] = '\0';
}

/**
 * Reads a fixed count of floats from one whitespace-separated column.
 * @param text Column text, not NUL-terminated.
 * @param out Receives one float per slot; untouched unless every slot parsed.
 * @return True when the column held exactly enough finite numbers.
 */
template <std::size_t N>
[[nodiscard]] bool read_floats(std::string_view text, std::array<float, N>& out) noexcept {
    std::array<char, 160> buffer{};
    const std::size_t length = (std::min)(text.size(), buffer.size() - 1);
    std::memcpy(buffer.data(), text.data(), length);
    buffer[length] = '\0';
    const char* cursor = buffer.data();
    std::array<float, N> parsed{};
    for (std::size_t index = 0; index < N; ++index) {
        char* next = nullptr;
        parsed[index] = std::strtof(cursor, &next);
        if (next == cursor || !std::isfinite(parsed[index])) {
            return false;
        }
        cursor = next;
    }
    out = parsed;
    return true;
}

/**
 * Parses one authored row: `name | combatant | x y z | qx qy qz qw`.
 * @param text One line, comments and blanks already rejected by the caller.
 * @param row Cleared by the caller; filled only on success.
 * @return True when all four columns parsed.
 */
[[nodiscard]] bool parse_row(std::string_view text, Row& row) noexcept {
    std::array<std::string_view, 4> columns{};
    for (std::size_t index = 0; index < columns.size(); ++index) {
        const std::size_t bar = text.find('|');
        if (index + 1 < columns.size() && bar == std::string_view::npos) {
            return false;
        }
        columns[index] = trim(bar == std::string_view::npos ? text : text.substr(0, bar));
        text = bar == std::string_view::npos ? std::string_view{} : text.substr(bar + 1);
    }
    if (columns[0].empty() || columns[1].empty()) {
        return false;
    }
    copy_into(row.name, columns[0]);
    copy_into(row.combatant, columns[1]);
    if (!read_floats(columns[2], row.position)) {
        return false;
    }
    if (!read_floats(columns[3], row.rotation)) {
        row.rotation = {0.0F, 0.0F, 0.0F, 1.0F};
    }
    return true;
}

/** @return Lower-cased copy of one character. */
[[nodiscard]] char lowered(char value) noexcept {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
}

/**
 * Finds a resident entity whose catalogue name contains the authored combatant name.
 *
 * The table names a combatant the way the mission content does (`phalanx`, `legionary`), while the
 * catalogue holds the display name (`Cabal Phalanx`). A contains-match bridges the two without
 * freezing a tag into the table, which would break the moment content moves.
 *
 * @param combatant Authored combatant name.
 * @param tag Receives the resident tag only on success.
 * @param matched Receives the catalogue name that matched, for the log line.
 * @return True when a resident entity matched.
 */
[[nodiscard]] bool resolve_combatant(std::string_view combatant,
                                     std::uint32_t& tag,
                                     std::array<char, 128>& matched) noexcept {
    if (combatant == kUnresolvedCombatant) {
        return false;
    }
    static std::vector<state::build_data::entity_names::Name> names;
    if (names.empty()) {
        names.resize(state::build_data::entity_names::count());
        std::size_t written = 0;
        if (names.empty() || !state::build_data::entity_names::snapshot(names, written)) {
            names.clear();
            return false;
        }
        names.resize(written);
    }
    for (const auto& entry : names) {
        const std::string_view text{entry.text.data(), entry.length};
        bool found = false;
        for (std::size_t start = 0; !found && start + combatant.size() <= text.size(); ++start) {
            std::size_t index = 0;
            while (index < combatant.size()
                   && lowered(text[start + index]) == lowered(combatant[index])) {
                ++index;
            }
            found = index == combatant.size();
        }
        if (!found || !spawn::is_tag_resident(entry.tag)) {
            continue;
        }
        tag = entry.tag;
        const std::size_t length = (std::min<std::size_t>)(entry.length, matched.size() - 1);
        std::memcpy(matched.data(), entry.text.data(), length);
        matched[length] = '\0';
        return true;
    }
    return false;
}

/**
 * Resolves the module this code lives in, so the table is looked up beside settings.json.
 * The path helper refuses a null module, and passing one made this function fail before it could
 * report anything, which reads exactly like a table that loaded and placed nothing.
 * @return This module, or null when the lookup fails.
 */
[[nodiscard]] HMODULE own_module() noexcept {
    HMODULE module = nullptr;
    const bool found = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                                              | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                          reinterpret_cast<LPCWSTR>(&trim),
                                          &module)
                       != FALSE;
    return found ? module : nullptr;
}

} // namespace

bool load() noexcept {
    core::path::Buffer tablePath;
    HMODULE module = own_module();
    if (module == nullptr || !core::path::artifact_directory(module, tablePath)
        || !core::path::append(tablePath, kTableSuffix)) {
        report("ev=encounter stage=load result=nopath");
        return false;
    }
    const HANDLE file = CreateFileW(tablePath.chars.data(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        report("ev=encounter stage=load result=absent");
        return false;
    }
    std::vector<char> text(kTableCapacity);
    DWORD read = 0;
    const bool ok = ReadFile(file, text.data(), static_cast<DWORD>(text.size()), &read, nullptr) != 0;
    CloseHandle(file);
    if (!ok) {
        report("ev=encounter stage=load result=unreadable");
        return false;
    }

    std::vector<Row> rows;
    std::string_view body{text.data(), read};
    while (!body.empty() && rows.size() < kRowCapacity) {
        const std::size_t breakAt = body.find('\n');
        const std::string_view line = trim(breakAt == std::string_view::npos
                                               ? body
                                               : body.substr(0, breakAt));
        body = breakAt == std::string_view::npos ? std::string_view{} : body.substr(breakAt + 1);
        if (line.empty() || line.front() == '#') {
            continue;
        }
        Row row{};
        if (parse_row(line, row)) {
            rows.push_back(row);
        }
    }

    AcquireSRWLockExclusive(&g_lock);
    g_rows = std::move(rows);
    g_placed.store(0, std::memory_order_relaxed);
    const std::size_t count = g_rows.size();
    ReleaseSRWLockExclusive(&g_lock);
    report("ev=encounter stage=load result=ok rows=%zu", count);
    return count > 0;
}

void clear() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    g_rows.clear();
    g_placed.store(0, std::memory_order_relaxed);
    ReleaseSRWLockExclusive(&g_lock);
}

std::size_t row_count() noexcept {
    AcquireSRWLockShared(&g_lock);
    const std::size_t count = g_rows.size();
    ReleaseSRWLockShared(&g_lock);
    return count;
}

std::size_t placed_count() noexcept {
    return g_placed.load(std::memory_order_relaxed);
}

void service() noexcept {
    const core::settings::client::Settings& client = core::settings::get().client;
    if (!client.encounterPlacementEnabled || !spawn::ready()) {
        return;
    }
    std::array<float, 3> player{};
    if (!teleport::current_position(player)) {
        return;
    }
    constexpr float radiusSquared = kPlacementRadius * kPlacementRadius;

    AcquireSRWLockExclusive(&g_lock);
    for (Row& row : g_rows) {
        if (row.placed) {
            continue;
        }
        const float dx = row.position[0] - player[0];
        const float dy = row.position[1] - player[1];
        const float dz = row.position[2] - player[2];
        if (dx * dx + dy * dy + dz * dz > radiusSquared) {
            continue;
        }
        std::uint32_t tag = 0;
        std::array<char, 128> matched{};
        const std::string_view combatant{row.combatant.data()};
        if (!resolve_combatant(combatant, tag, matched)) {
            // Mark it done either way: an unresolved combatant will not resolve on the next frame,
            // and retrying every frame would search the whole catalogue at frame rate.
            row.placed = true;
            report("ev=encounter stage=place result=unresolved squad=%s combatant=%s",
                   row.name.data(),
                   row.combatant.data());
            continue;
        }
        row.placed = true;
        const std::array<float, 3> position = row.position;
        const std::array<float, 4> rotation = row.rotation;
        const std::array<char, 64> name = row.name;
        ReleaseSRWLockExclusive(&g_lock);

        const bool requested = spawn::place_at(tag, position, rotation, 1.0F);
        report("ev=encounter stage=place result=%s squad=%s entity=%s tag=0x%08X pos=%.1f,%.1f,%.1f",
               requested ? "ok" : "refused",
               name.data(),
               matched.data(),
               tag,
               static_cast<double>(position[0]),
               static_cast<double>(position[1]),
               static_cast<double>(position[2]));
        if (requested) {
            g_placed.fetch_add(1, std::memory_order_relaxed);
        }
        return;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

} // namespace sunrise::client::hooks::spawn::encounter
