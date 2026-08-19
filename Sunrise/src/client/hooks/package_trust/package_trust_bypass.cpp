#include "package_trust_bypass.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../executable/image.h"
#include "../../hooking/detour.h"
#include "../../patterns/image_scan.h"

namespace sunrise::client::hooks::package_trust {
namespace {

using patterns::scan_main_image_unique;
using patterns::signature;
using patterns::signature_length;

/**
 * Native package-header validator. The matched prologue tests its sixth argument and returns -93
 * when RSA verification did not mark the header trusted. The following bytes enter the ordinary
 * structural checks, keeping this target distinct from the RSA implementation itself.
 */
constexpr std::string_view kValidatorSignatureText =
    "40 53 48 83 EC 20 80 7C 24 58 00 44 0F B7 DA 4C 8B D1 BB 01 00 00 00 "
    "75 0D BB A3 FF FF FF 8B C3 48 83 C4 20 5B C3";
/** Masked form of the validator text, which is the form the image scan takes. */
constexpr auto kValidatorSignature =
    signature<signature_length(kValidatorSignatureText)>(kValidatorSignatureText);

/**
 * The patchable registrar's extended-header authentication failure. Native code loads -89 here,
 * then joins the common result/cleanup path. The site is unique in this client build.
 */
constexpr std::string_view kExtendedHeaderFailureText = "B8 A7 FF FF FF E9 ? ? ? ?";
constexpr auto kExtendedHeaderFailure =
    signature<signature_length(kExtendedHeaderFailureText)>(kExtendedHeaderFailureText);

/**
 * Cached-data authentication gate used while registering/loading base packages. The hash routine
 * returns a boolean in AL. Native code conditionally jumps to the ordinary success continuation;
 * otherwise it enters the unique "Failed to validate cached data hash" error path with -89.
 */
constexpr std::string_view kCachedDataHashGateText =
    "84 C0 0F 85 ? ? ? ? E9 ? ? ? ? 48 8B 45 48 89 08";
/** Masked form of the gate text, which is the form the image scan takes. */
constexpr auto kCachedDataHashGate =
    signature<signature_length(kCachedDataHashGateText)>(kCachedDataHashGateText);

/** Only the MOV EAX immediate changes; the native continuation remains untouched. */
constexpr std::size_t kResultImmediateOffset = 1;
constexpr std::array<std::byte, 4> kSuccessResult{
    std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

/** Replace JNZ rel32 (0F 85) with NOP; JMP rel32 (90 E9), retaining its native destination. */
constexpr std::size_t kCachedDataBranchOffset = 2;
constexpr std::array<std::byte, 2> kAlwaysTakeSuccessBranch{std::byte{0x90}, std::byte{0xE9}};

/** ABI recovered from the validator's native call site. */
using ValidateHeader = std::int32_t(__fastcall*)(const std::uint32_t* validationMask,
                                                 std::uint16_t packageGroup,
                                                 std::uint64_t buildSignature,
                                                 std::int32_t expectedFileSize,
                                                 std::uint16_t localeToken,
                                                 std::uint8_t rsaTrusted,
                                                 const void* header) noexcept;

hooking::detour::Handle g_handle{};
std::byte* g_extendedHeaderResult{};
std::array<std::byte, kSuccessResult.size()> g_extendedHeaderOriginal{};
std::byte* g_cachedDataBranch{};
std::array<std::byte, kAlwaysTakeSuccessBranch.size()> g_cachedDataBranchOriginal{};

/** Writes instruction bytes and restores the page's original protection. */
template <std::size_t Size>
[[nodiscard]] bool write_code(std::byte* destination,
                              const std::array<std::byte, Size>& value) noexcept {
    if (destination == nullptr) {
        return false;
    }
    DWORD originalProtection = 0;
    if (VirtualProtect(destination, value.size(), PAGE_EXECUTE_READWRITE, &originalProtection)
        == FALSE) {
        return false;
    }
    std::memcpy(destination, value.data(), value.size());
    FlushInstructionCache(GetCurrentProcess(), destination, value.size());
    DWORD ignored = 0;
    return VirtualProtect(destination, value.size(), originalProtection, &ignored) != FALSE;
}

/** Runs every native validation rule while forcing only the RSA result to trusted. */
std::int32_t __fastcall validate_header(const std::uint32_t* validationMask,
                                        std::uint16_t packageGroup,
                                        std::uint64_t buildSignature,
                                        std::int32_t expectedFileSize,
                                        std::uint16_t localeToken,
                                        std::uint8_t,
                                        const void* header) noexcept {
    if (header != nullptr) {
        const auto* const bytes = static_cast<const std::byte*>(header);
        std::uint16_t packageId = 0;
        std::uint16_t patchId = 0;
        std::uint32_t headerFileSize = 0;
        std::memcpy(&packageId, bytes + 0x04, sizeof packageId);
        std::memcpy(&patchId, bytes + 0x20, sizeof patchId);
        std::memcpy(&headerFileSize, bytes + 0x164, sizeof headerFileSize);
        if (headerFileSize != static_cast<std::uint32_t>(expectedFileSize)) {
            std::array<char, 256> event{};
            const int length = std::snprintf(event.data(),
                                             event.size(),
                                             "ev=package_trust stage=header_size result=mismatch "
                                             "package=0x%04X patch=%u header=%u expected=%u",
                                             packageId,
                                             patchId,
                                             headerFileSize,
                                             static_cast<std::uint32_t>(expectedFileSize));
            if (length > 0) {
                core::log::write(core::log::Channel::client,
                                 core::log::Level::error,
                                 std::string_view(event.data(),
                                                  (std::min)(static_cast<std::size_t>(length),
                                                             event.size() - 1)));
            }
        }
    }
    const auto original = reinterpret_cast<ValidateHeader>(g_handle.original);
    return original(
        validationMask, packageGroup, buildSignature, expectedFileSize, localeToken, 1, header);
}

/** DIAG ONLY: reports the sites that load one negative result code into eax in the loaded image. */
void diag_scan_code(std::int32_t code) noexcept {
    executable::ExecutableImage main{};
    if (!executable::inspect_main_module(main)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=diag stage=code_scan result=no_image");
        return;
    }
    std::array<std::byte, 5> pattern{};
    pattern[0] = std::byte{0xB8};
    const auto value = static_cast<std::uint32_t>(code);
    for (std::size_t index = 0; index < 4; ++index) {
        pattern[index + 1] = static_cast<std::byte>((value >> (index * 8U)) & 0xFFU);
    }
    std::size_t found = 0;
    std::array<std::byte*, 8> hits{};
    for (std::size_t section = 0; section < main.count; ++section) {
        const std::span<std::byte> span = main.sections[section];
        if (span.size() < pattern.size()) {
            continue;
        }
        for (std::size_t offset = 0; offset + pattern.size() <= span.size(); ++offset) {
            if (std::memcmp(span.data() + offset, pattern.data(), pattern.size()) != 0) {
                continue;
            }
            if (found < hits.size()) {
                hits[found] = span.data() + offset;
            }
            ++found;
        }
    }
    std::array<char, core::log::kLineCapacity> line{};
    int written = std::snprintf(line.data(),
                                line.size(),
                                "ev=diag stage=code_scan code=%d sections=%zu sites=%zu",
                                code,
                                main.count,
                                found);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    const std::size_t shown = found < hits.size() ? found : hits.size();
    for (std::size_t index = 0; index < shown; ++index) {
        written = std::snprintf(line.data(),
                                line.size(),
                                "ev=diag stage=code_site code=%d index=%zu address=%p",
                                code,
                                index,
                                static_cast<void*>(hits[index]));
        if (written > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
}

} // namespace

/** Attaches the native package-header trust bypass. */
bool install() noexcept {
    if (g_handle.attached) {
        return true;
    }
    std::byte* const target =
        scan_main_image_unique(kValidatorSignature, "package_header_validator");
    std::byte* const extendedHeaderFailure =
        scan_main_image_unique(kExtendedHeaderFailure, "package_extended_header_failure");
    std::byte* const cachedDataHashGate =
        scan_main_image_unique(kCachedDataHashGate, "package_cached_data_hash_gate");
    if (target == nullptr || extendedHeaderFailure == nullptr || cachedDataHashGate == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=package_trust stage=resolve result=fail");
        return false;
    }
    const hooking::detour::Spec spec{target, reinterpret_cast<void*>(&validate_header)};
    if (!hooking::detour::install(spec, g_handle)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=package_trust stage=attach result=fail");
        return false;
    }
    g_extendedHeaderResult = extendedHeaderFailure + kResultImmediateOffset;
    std::memcpy(
        g_extendedHeaderOriginal.data(), g_extendedHeaderResult, g_extendedHeaderOriginal.size());
    if (!write_code(g_extendedHeaderResult, kSuccessResult)) {
        (void)hooking::detour::uninstall(g_handle);
        g_extendedHeaderResult = nullptr;
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=package_trust stage=extended_header result=fail");
        return false;
    }
    g_cachedDataBranch = cachedDataHashGate + kCachedDataBranchOffset;
    std::memcpy(
        g_cachedDataBranchOriginal.data(), g_cachedDataBranch, g_cachedDataBranchOriginal.size());
    if (!write_code(g_cachedDataBranch, kAlwaysTakeSuccessBranch)) {
        (void)write_code(g_extendedHeaderResult, g_extendedHeaderOriginal);
        (void)hooking::detour::uninstall(g_handle);
        g_extendedHeaderResult = nullptr;
        g_cachedDataBranch = nullptr;
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=package_trust stage=cached_data result=fail");
        return false;
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=package_trust stage=attach result=ok mode=package_integrity_bypass");
    // DIAG ONLY: -89 is a positive control the mod already patches; -86 is the unhandled code.
    diag_scan_code(-89);
    diag_scan_code(-95);
    diag_scan_code(-86);
    return true;
}

/** Detaches the native package-header trust bypass. */
bool uninstall() noexcept {
    bool restored = true;
    if (g_cachedDataBranch != nullptr) {
        const bool cachedDataRestored = write_code(g_cachedDataBranch, g_cachedDataBranchOriginal);
        restored = restored && cachedDataRestored;
        if (cachedDataRestored) {
            g_cachedDataBranch = nullptr;
        }
    }
    if (g_extendedHeaderResult != nullptr) {
        const bool extendedHeaderRestored =
            write_code(g_extendedHeaderResult, g_extendedHeaderOriginal);
        restored = restored && extendedHeaderRestored;
        if (extendedHeaderRestored) {
            g_extendedHeaderResult = nullptr;
        }
    }
    const bool detached = !g_handle.attached || hooking::detour::uninstall(g_handle);
    return restored && detached;
}

/** @return True while the validator detour is attached. */
bool is_installed() noexcept {
    return g_handle.attached && g_extendedHeaderResult != nullptr && g_cachedDataBranch != nullptr;
}

} // namespace sunrise::client::hooks::package_trust
