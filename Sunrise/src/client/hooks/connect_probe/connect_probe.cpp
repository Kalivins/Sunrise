/**
 * Read-only entry probe for the functions that call the peer channel connect.
 *
 * The client enters `activity:physics_join`, waits about six seconds, leaves for reason
 * `unavailable`, and never calls `NetChannel_RequestConnectForFamily` - measured in a mission and in
 * a social destination alike, so the failure is general rather than mission-specific. Six direct call
 * sites reach that connect; the question this probe answers is which of their enclosing functions run
 * at all, because a guard cannot be blamed for a function that is never entered.
 *
 * Three of the five enclosing functions are covered. The other two (`0x0170230A`, `0x017B8B54`) are
 * excluded on purpose: each sits immediately after the previous function's last byte with no padding
 * gap, which marks them as chunks of a split function rather than entries. Detouring a chunk boundary
 * corrupts execution, so they are left alone and their two sites stay uncovered.
 *
 * The probe changes no behaviour: it logs, forwards every argument, and returns what the original
 * returned. Each detour declares eight parameters and passes all of them on. The argument count of
 * these functions is unknown, and at detour entry the stack is exactly as the real call left it, so
 * forwarding eight reads arguments five to eight from the right place. Declaring too few would leave
 * a real callee reading stack slots this frame never wrote, which corrupts silently and is worse than
 * a crash.
 */

#include "connect_probe.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../hooking/detour.h"
#include "../../patterns/image_scan.h"
#include "../../patterns/signature_text.h"

namespace sunrise::client::hooks::connect_probe {
namespace {

using patterns::scan_main_image_unique;
using patterns::signature;
using patterns::signature_length;

/** How many entries each probe reports before going quiet, so a hot function cannot flood the log. */
constexpr unsigned kReportsPerSite = 3;

/**
 * Unknown arity, so eight parameters are declared and all eight are forwarded. See the file comment:
 * this is what keeps a callee with more than four arguments reading its own stack slots.
 */
using Probed = std::int64_t(__fastcall*)(void*, void*, void*, void*, void*, void*, void*, void*);

/** Encloses the call site at 0x01783AF7. Unique at 24 bytes. */
constexpr std::string_view kSiteASignatureText =
    "48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 90 FD FF FF";
/** Encloses the call sites at 0x0178EAAE and 0x0178F0F6. Unique at 20 bytes. */
constexpr std::string_view kSiteBSignatureText =
    "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 88 D7 FF";
/** Encloses the call site at 0x017B341E. Unique at 24 bytes. */
constexpr std::string_view kSiteCSignatureText =
    "48 89 5C 24 18 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 70 FD FF FF";

constexpr auto kSiteASignature = signature<signature_length(kSiteASignatureText)>(kSiteASignatureText);
constexpr auto kSiteBSignature = signature<signature_length(kSiteBSignatureText)>(kSiteBSignatureText);
constexpr auto kSiteCSignature = signature<signature_length(kSiteCSignatureText)>(kSiteCSignatureText);

hooking::detour::Handle g_handleA{};
hooking::detour::Handle g_handleB{};
hooking::detour::Handle g_handleC{};
std::atomic<unsigned> g_countA{};
std::atomic<unsigned> g_countB{};
std::atomic<unsigned> g_countC{};

/**
 * Reports one entry, up to the per-site cap.
 * @param name Site label carried into the log line.
 * @param counter Per-site report counter.
 */
void report_entry(const char* name, std::atomic<unsigned>& counter) noexcept {
    const unsigned seen = counter.fetch_add(1, std::memory_order_relaxed);
    if (seen >= kReportsPerSite) {
        return;
    }
    std::array<char, 96> line{};
    const int written = std::snprintf(
        line.data(), line.size(), "ev=connect_probe stage=enter site=%s n=%u", name, seen + 1);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

__declspec(noinline)
/** Entry probe for site A. Forwards every argument and the original result. */
std::int64_t __fastcall probe_a(void* a1, void* a2, void* a3, void* a4,
                                void* a5, void* a6, void* a7, void* a8) noexcept {
    report_entry("A", g_countA);
    const auto original = reinterpret_cast<Probed>(g_handleA.original);
    return original == nullptr ? 0 : original(a1, a2, a3, a4, a5, a6, a7, a8);
}

__declspec(noinline)
/** Entry probe for site B, which encloses two of the six call sites. */
std::int64_t __fastcall probe_b(void* a1, void* a2, void* a3, void* a4,
                                void* a5, void* a6, void* a7, void* a8) noexcept {
    report_entry("B", g_countB);
    const auto original = reinterpret_cast<Probed>(g_handleB.original);
    return original == nullptr ? 0 : original(a1, a2, a3, a4, a5, a6, a7, a8);
}

__declspec(noinline)
/** Entry probe for site C. */
std::int64_t __fastcall probe_c(void* a1, void* a2, void* a3, void* a4,
                                void* a5, void* a6, void* a7, void* a8) noexcept {
    report_entry("C", g_countC);
    const auto original = reinterpret_cast<Probed>(g_handleC.original);
    return original == nullptr ? 0 : original(a1, a2, a3, a4, a5, a6, a7, a8);
}

/**
 * Attaches one probe, reporting its own outcome so a missing target is never silent.
 * @param text Signature bytes, only for the log line.
 * @param target Resolved address, or nullptr when the scan found nothing unique.
 * @param replacement Detour body.
 * @param handle Receives the attachment.
 * @param name Site label.
 * @return True when the detour attached.
 */
[[nodiscard]] bool attach(std::byte* target,
                          void* replacement,
                          hooking::detour::Handle& handle,
                          const char* name) noexcept {
    std::array<char, 96> line{};
    if (target == nullptr) {
        const int written = std::snprintf(
            line.data(), line.size(), "ev=connect_probe stage=attach site=%s result=fail reason=target", name);
        if (written > 0) {
            core::log::write(core::log::Channel::client, core::log::Level::warn,
                             {line.data(), static_cast<std::size_t>(written)});
        }
        return false;
    }
    const hooking::detour::Spec spec{target, replacement};
    const bool attached = hooking::detour::install(spec, handle);
    const int written = std::snprintf(line.data(), line.size(),
                                      "ev=connect_probe stage=attach site=%s result=%s",
                                      name, attached ? "ok" : "fail");
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         attached ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return attached;
}

} // namespace

/** Attaches the connect-path entry probe. */
bool install() noexcept {
    bool any = false;
    if (!g_handleA.attached) {
        any = attach(scan_main_image_unique(kSiteASignature, "connect_probe_a"),
                     reinterpret_cast<void*>(&probe_a), g_handleA, "A")
              || any;
    }
    if (!g_handleB.attached) {
        any = attach(scan_main_image_unique(kSiteBSignature, "connect_probe_b"),
                     reinterpret_cast<void*>(&probe_b), g_handleB, "B")
              || any;
    }
    if (!g_handleC.attached) {
        any = attach(scan_main_image_unique(kSiteCSignature, "connect_probe_c"),
                     reinterpret_cast<void*>(&probe_c), g_handleC, "C")
              || any;
    }
    return any;
}

/** Detaches the connect-path entry probe. */
void uninstall() noexcept {
    if (g_handleA.attached) {
        (void)hooking::detour::uninstall(g_handleA);
    }
    if (g_handleB.attached) {
        (void)hooking::detour::uninstall(g_handleB);
    }
    if (g_handleC.attached) {
        (void)hooking::detour::uninstall(g_handleC);
    }
    g_countA.store(0, std::memory_order_release);
    g_countB.store(0, std::memory_order_release);
    g_countC.store(0, std::memory_order_release);
}

} // namespace sunrise::client::hooks::connect_probe
