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
#include <imgui.h>
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

/** What a row asks for. Only `squad` has a consumer today; the rest are authored ahead of theirs. */
enum class Kind : std::uint8_t {
    squad,    ///< place a combatant
    wave,     ///< a group of squads released together
    trigger,  ///< a volume that fires other rows
    door,     ///< a door and what unlocks it
    voice,    ///< a line of dialogue and its subtitle
    music,    ///< a music stem transition
    unknown,
};

struct Row {
    Kind kind{Kind::unknown};
    std::array<char, 64> name{};
    std::array<char, 192> args{};
    std::array<float, 3> position{};
    std::array<float, 4> rotation{};
    bool placed{};
};

/** @return The kind one authored word names, or unknown. */
[[nodiscard]] Kind kind_of(std::string_view text) noexcept {
    if (text == "squad") { return Kind::squad; }
    if (text == "wave") { return Kind::wave; }
    if (text == "trigger") { return Kind::trigger; }
    if (text == "door") { return Kind::door; }
    if (text == "voice") { return Kind::voice; }
    if (text == "music") { return Kind::music; }
    return Kind::unknown;
}

/** @return The authored word for one kind, for a log line. */
[[nodiscard]] const char* kind_name(Kind kind) noexcept {
    switch (kind) {
    case Kind::squad: return "squad";
    case Kind::wave: return "wave";
    case Kind::trigger: return "trigger";
    case Kind::door: return "door";
    case Kind::voice: return "voice";
    case Kind::music: return "music";
    default: return "unknown";
    }
}

/**
 * Reads one value out of a key=value argument bag.
 * @param args Whole argument column, space separated.
 * @param key Key to find, without its equals sign.
 * @return The value, or empty when the key is absent.
 */
[[nodiscard]] std::string_view argument(std::string_view args, std::string_view key) noexcept {
    while (!args.empty()) {
        const std::size_t space = args.find(' ');
        const std::string_view pair = space == std::string_view::npos ? args : args.substr(0, space);
        args = space == std::string_view::npos ? std::string_view{} : args.substr(space + 1);
        const std::size_t equals = pair.find('=');
        if (equals != std::string_view::npos && pair.substr(0, equals) == key) {
            return pair.substr(equals + 1);
        }
    }
    return {};
}

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

void copy_into128(std::array<char, 128>& field, std::string_view text) noexcept {
    const std::size_t length = (std::min)(text.size(), field.size() - 1);
    std::memcpy(field.data(), text.data(), length);
    field[length] = '\0';
}

template <std::size_t N>
void copy_into(std::array<char, N>& field, std::string_view text) noexcept {
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
 * Parses one authored row: `kind | name | args | x y z | qx qy qz qw`.
 * @param text One line, comments and blanks already rejected by the caller.
 * @param row Cleared by the caller; filled only on success.
 * @return True when all four columns parsed.
 */
[[nodiscard]] bool parse_row(std::string_view text, Row& row) noexcept {
    std::array<std::string_view, 5> columns{};
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
    row.kind = kind_of(columns[0]);
    copy_into(row.name, columns[1]);
    copy_into(row.args, columns[2]);
    if (!read_floats(columns[3], row.position)) {
        return false;
    }
    if (!read_floats(columns[4], row.rotation)) {
        row.rotation = {0.0F, 0.0F, 0.0F, 1.0F};
    }
    return true;
}

/**
 * Parses a `0x`-prefixed or bare hex tag from an argument value.
 * @param text Argument value, e.g. "0x80c1a52d".
 * @return The tag, or zero when the text is not hex (zero is never a valid tag).
 */
[[nodiscard]] std::uint32_t parse_tag(std::string_view text) noexcept {
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
    }
    if (text.empty() || text.size() > 8) {
        return 0;
    }
    std::uint32_t value = 0;
    for (const char c : text) {
        std::uint32_t digit;
        if (c >= '0' && c <= '9') {
            digit = static_cast<std::uint32_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<std::uint32_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<std::uint32_t>(c - 'A' + 10);
        } else {
            return 0;
        }
        value = (value << 4) | digit;
    }
    return value;
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
/** Why a combatant name did or did not become a placeable tag. */
enum class Resolution {
    resolved,      ///< a catalogue name matched and its tag is resident
    nonResident,   ///< a name matched but its definition is not streamed in (the streaming wall)
    noName,        ///< no catalogue name contained the authored word (a table typo, or "?")
};

[[nodiscard]] bool name_contains(std::string_view text, std::string_view needle) noexcept {
    for (std::size_t start = 0; start + needle.size() <= text.size(); ++start) {
        std::size_t index = 0;
        while (index < needle.size() && lowered(text[start + index]) == lowered(needle[index])) {
            ++index;
        }
        if (index == needle.size()) {
            return true;
        }
    }
    return false;
}

/**
 * Resolves an authored combatant name to a resident tag.
 *
 * A name that matches the catalogue but whose definition is not streamed in is reported apart from a
 * name that matches nothing: the first is the streaming wall, the second is a table typo, and only
 * separating them tells a run which it hit. The matched name is filled in the non-resident case too,
 * so the log names the exact definition a mission would need made resident.
 */
[[nodiscard]] Resolution resolve_combatant(std::string_view combatant,
                                           std::uint32_t& tag,
                                           std::array<char, 128>& matched) noexcept {
    if (combatant == kUnresolvedCombatant) {
        return Resolution::noName;
    }
    static std::vector<state::build_data::entity_names::Name> names;
    if (names.empty()) {
        names.resize(state::build_data::entity_names::count());
        std::size_t written = 0;
        if (names.empty() || !state::build_data::entity_names::snapshot(names, written)) {
            names.clear();
            return Resolution::noName;
        }
        names.resize(written);
    }
    bool matchedName = false;
    for (const auto& entry : names) {
        if (!name_contains({entry.text.data(), entry.length}, combatant)) {
            continue;
        }
        // Remember the first matching name even if it is not resident, so a run that hits only the
        // streaming wall still reports the definition it was reaching for.
        if (!matchedName) {
            matchedName = true;
            const std::size_t length = (std::min<std::size_t>)(entry.length, matched.size() - 1);
            std::memcpy(matched.data(), entry.text.data(), length);
            matched[length] = '\0';
        }
        if (spawn::is_tag_resident(entry.tag)) {
            tag = entry.tag;
            const std::size_t length = (std::min<std::size_t>)(entry.length, matched.size() - 1);
            std::memcpy(matched.data(), entry.text.data(), length);
            matched[length] = '\0';
            return Resolution::resolved;
        }
    }
    return matchedName ? Resolution::nonResident : Resolution::noName;
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

/** Rows written by the recorder are numbered from this, so a table stays readable. */
std::atomic<unsigned> g_recorded{0};
/** What the next recorded row will be. Set from the panel, so one walk can author several kinds. */
std::atomic<Kind> g_recordKind{Kind::squad};
/** Arguments the next recorded row carries, normally the entity the panel has selected. */
std::array<char, 192> g_recordArgs{};
SRWLOCK g_recordLock = SRWLOCK_INIT;

/**
 * Builds the table path once, so the recorder and the loader cannot disagree about where it lives.
 * @param output Receives the full path.
 * @return True when the path resolved.
 */
[[nodiscard]] bool table_path(core::path::Buffer& output) noexcept {
    HMODULE module = own_module();
    return module != nullptr && core::path::artifact_directory(module, output)
           && core::path::append(output, kTableSuffix);
}

} // namespace

void configure_recorder(std::string_view kind, std::string_view args) noexcept {
    g_recordKind.store(kind_of(kind), std::memory_order_relaxed);
    AcquireSRWLockExclusive(&g_recordLock);
    copy_into(g_recordArgs, args);
    ReleaseSRWLockExclusive(&g_recordLock);
}

bool draw_markers() noexcept {
    if (!core::settings::get().client.encounterMarkersEnabled) {
        return false;
    }
    std::array<float, 3> eye{};
    std::array<float, 3> forward{};
    if (!teleport::current_camera_pose(eye, forward)) {
        return false;
    }
    const float length =
        std::sqrt(forward[0] * forward[0] + forward[1] * forward[1] + forward[2] * forward[2]);
    if (!(length > 1.0e-4F)) {
        return false;
    }
    const std::array<float, 3> ahead{forward[0] / length, forward[1] / length, forward[2] / length};
    // Right and up from world up, so a marker keeps its place when the camera pitches. Roll is
    // assumed zero, which holds for a first-person camera on foot.
    std::array<float, 3> right{ahead[1], -ahead[0], 0.0F};
    const float rightLength = std::sqrt(right[0] * right[0] + right[1] * right[1]);
    if (!(rightLength > 1.0e-4F)) {
        return false;
    }
    right = {right[0] / rightLength, right[1] / rightLength, 0.0F};
    const std::array<float, 3> up{right[1] * ahead[2] - right[2] * ahead[1],
                                  right[2] * ahead[0] - right[0] * ahead[2],
                                  right[0] * ahead[1] - right[1] * ahead[0]};

    const ImVec2 screen = ImGui::GetIO().DisplaySize;
    if (screen.x < 2.0F || screen.y < 2.0F) {
        return false;
    }
    // The horizontal field of view is a setting rather than a read of the account value, because a
    // marker that lands beside its object is worse than none, and correcting the projection should
    // not cost a build. The default matches the account default.
    const auto degrees = static_cast<float>(core::settings::get().client.encounterMarkerFov);
    const float fov = (degrees > 30.0F && degrees < 170.0F ? degrees : 85.0F) * 3.14159265F / 180.0F;
    const float focal = (screen.x * 0.5F) / std::tan(fov * 0.5F);
    ImDrawList* const list = ImGui::GetForegroundDrawList();
    unsigned drawn = 0;

    AcquireSRWLockShared(&g_lock);
    for (const Row& row : g_rows) {
        const std::array<float, 3> delta{row.position[0] - eye[0],
                                         row.position[1] - eye[1],
                                         row.position[2] - eye[2]};
        const float depth =
            delta[0] * ahead[0] + delta[1] * ahead[1] + delta[2] * ahead[2];
        if (depth < 1.0F) {
            continue;
        }
        const float across = delta[0] * right[0] + delta[1] * right[1] + delta[2] * right[2];
        const float rise = delta[0] * up[0] + delta[1] * up[1] + delta[2] * up[2];
        const ImVec2 at{screen.x * 0.5F + across / depth * focal,
                        screen.y * 0.5F - rise / depth * focal};
        if (at.x < -60.0F || at.y < -40.0F || at.x > screen.x + 60.0F || at.y > screen.y + 40.0F) {
            continue;
        }
        // A row that placed reads as done; one still waiting reads as work. The distance is what
        // decides whether walking further is worth it, so it travels with the name.
        const ImU32 tint = row.placed ? IM_COL32(120, 200, 160, 210) : IM_COL32(212, 140, 90, 230);
        list->AddCircle(at, 7.0F, tint, 0, 2.0F);
        list->AddLine(ImVec2(at.x - 11.0F, at.y), ImVec2(at.x - 3.0F, at.y), tint, 1.5F);
        list->AddLine(ImVec2(at.x + 3.0F, at.y), ImVec2(at.x + 11.0F, at.y), tint, 1.5F);
        std::array<char, 96> label{};
        const int written = std::snprintf(label.data(),
                                          label.size(),
                                          "%s  %.0fm",
                                          row.name.data(),
                                          static_cast<double>(depth));
        if (written > 0) {
            const ImVec2 text{at.x + 14.0F, at.y - 7.0F};
            list->AddText(ImVec2(text.x + 1.0F, text.y + 1.0F), IM_COL32(0, 0, 0, 170), label.data());
            list->AddText(text, tint, label.data());
        }
        ++drawn;
    }
    ReleaseSRWLockShared(&g_lock);
    return drawn != 0;
}

bool record_here() noexcept {
    std::array<float, 3> player{};
    if (!teleport::current_position(player)) {
        report("ev=encounter stage=record result=noposition");
        return false;
    }
    core::path::Buffer path;
    if (!table_path(path)) {
        report("ev=encounter stage=record result=nopath");
        return false;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    FILE_APPEND_DATA,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    OPEN_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        report("ev=encounter stage=record result=unwritable");
        return false;
    }
    const unsigned ordinal = g_recorded.fetch_add(1, std::memory_order_relaxed) + 1;
    const Kind kind = g_recordKind.load(std::memory_order_relaxed);
    AcquireSRWLockShared(&g_recordLock);
    std::array<char, 192> args = g_recordArgs;
    ReleaseSRWLockShared(&g_recordLock);
    if (args[0] == '\0') {
        args[0] = '?';
        args[1] = '\0';
    }
    std::array<char, 384> row{};
    // The combatant stays unresolved: which enemy belongs here is a decision, and a guessed name
    // would sit in a file whose other rows are extracted fact.
    const int written = std::snprintf(row.data(),
                                      row.size(),
                                      "%s | recorded_%u | %s | %.3f %.3f %.3f | "
                                      "0.0000 0.0000 0.0000 1.0000\r\n",
                                      kind_name(kind),
                                      ordinal,
                                      args.data(),
                                      static_cast<double>(player[0]),
                                      static_cast<double>(player[1]),
                                      static_cast<double>(player[2]));
    DWORD put = 0;
    const bool ok = written > 0
                    && WriteFile(file, row.data(), static_cast<DWORD>(written), &put, nullptr) != 0;
    CloseHandle(file);
    report("ev=encounter stage=record result=%s kind=%s row=recorded_%u pos=%.1f,%.1f,%.1f",
           ok ? "ok" : "fail",
           kind_name(kind),
           ordinal,
           static_cast<double>(player[0]),
           static_cast<double>(player[1]),
           static_cast<double>(player[2]));
    return ok;
}

bool load() noexcept {
    core::path::Buffer tablePath;
    if (!table_path(tablePath)) {
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
    // The recorder answers even when placement is off: authoring a table and populating from one are
    // separate jobs, and needing the second to do the first would place squads over the surveyor.
    const bool down = (GetAsyncKeyState(VK_F6) & 0x8000) != 0;
    static bool wasDown = false;
    if (down && !wasDown) {
        (void)record_here();
    }
    wasDown = down;

    if (!client.encounterPlacementEnabled || !spawn::ready()) {
        return;
    }
    std::array<float, 3> player{};
    if (!teleport::current_position(player)) {
        return;
    }
    const float radius = static_cast<float>(client.encounterPlacementRadius);
    const float radiusSquared = radius * radius;

    // Periodic witness. A service that never runs and one that runs but matches nothing look the
    // same in an empty log, so report the player position against the closest authored row.
    static std::atomic<std::uint64_t> g_nextProbe{0};
    static std::atomic<unsigned> g_probes{0};
    const std::uint64_t now = GetTickCount64();
    if (now >= g_nextProbe.load(std::memory_order_relaxed)
        && g_probes.fetch_add(1, std::memory_order_relaxed) < 8) {
        g_nextProbe.store(now + 3000, std::memory_order_relaxed);
        AcquireSRWLockShared(&g_lock);
        float best = -1.0F;
        const char* nearest = "none";
        for (const Row& row : g_rows) {
            const float dx = row.position[0] - player[0];
            const float dy = row.position[1] - player[1];
            const float dz = row.position[2] - player[2];
            const float distance = std::sqrt(dx * dx + dy * dy + dz * dz);
            if (best < 0.0F || distance < best) {
                best = distance;
                nearest = row.name.data();
            }
        }
        const std::size_t rows = g_rows.size();
        ReleaseSRWLockShared(&g_lock);
        report("ev=encounter stage=probe player=%.1f,%.1f,%.1f nearest=%s distance=%.1f rows=%zu",
               static_cast<double>(player[0]),
               static_cast<double>(player[1]),
               static_cast<double>(player[2]),
               nearest,
               static_cast<double>(best),
               rows);
    }

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
        if (row.kind != Kind::squad) {
            // Authored ahead of its consumer. Say so once rather than silently ignoring a row the
            // author walked out to record.
            row.placed = true;
            report("ev=encounter stage=place result=nokind kind=%s row=%s",
                   kind_name(row.kind),
                   row.name.data());
            continue;
        }
        std::uint32_t tag = 0;
        std::array<char, 128> matched{};
        const std::string_view args{row.args.data()};
        Resolution resolution;
        const std::uint32_t authoredTag = parse_tag(argument(args, "tag"));
        if (authoredTag != 0) {
            // The content names its combatant by definition tag, which place_at consumes directly.
            // Label the log with the human name when the table carries one, else the tag itself.
            const std::string_view label = argument(args, "combatant");
            copy_into128(matched, label.empty() || label == kUnresolvedCombatant
                                      ? std::string_view{argument(args, "tag")}
                                      : label);
            if (spawn::is_tag_resident(authoredTag)) {
                tag = authoredTag;
                resolution = Resolution::resolved;
            } else {
                resolution = Resolution::nonResident;
            }
        } else {
            const std::string_view combatant = argument(args, "combatant");
            resolution = resolve_combatant(combatant, tag, matched);
        }
        if (resolution != Resolution::resolved) {
            // Mark it done either way: neither wall clears on the next frame, and retrying every
            // frame would search the whole catalogue at frame rate. A non-resident definition names
            // what it reached for, so the log doubles as the residency inventory a mission needs;
            // a no-name row points at a table typo instead.
            row.placed = true;
            if (resolution == Resolution::nonResident) {
                report("ev=encounter stage=place result=nonresident squad=%s entity=%s args=%s",
                       row.name.data(),
                       matched.data(),
                       row.args.data());
            } else {
                report("ev=encounter stage=place result=noname squad=%s args=%s",
                       row.name.data(),
                       row.args.data());
            }
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
