#include "matchmaking_route.h"

#include <Windows.h>

#include <array>
#include <cstdio>

#include "../../../../core/logging/log.h"

#include "../../../../middleware/bap/matchmaking/request/matchmaking_request_parser.h"
#include "../../../../middleware/bap/matchmaking/response/matchmaking_response_encoder.h"

namespace sunrise::server::bap::encrypted::matchmaking {
namespace {

namespace service = middleware::bap::matchmaking;

/** Middleware parsing and State storage must accept the same runtime descriptor size. */
static_assert(service::kJoinDescriptorSize == state::matchmaking::kDescriptorSize);

/**
 * Finds the State-backed fields for the request kinds that are not static.
 * @param context Active logical matchmaking context.
 * @param request Fully validated request fields with a borrowed descriptor.
 * @param response Receives the response shape and any id State picked.
 * @param mutation Receives a prepared update without committing persistent State.
 * @return True when the request is static or all required State fields are available.
 */
[[nodiscard]] bool prepare_fields(state::matchmaking::ContextHandle context,
                                  const service::Request& request,
                                  service::Response& response,
                                  state::matchmaking::PendingMutation& mutation) noexcept {
    response.kind = request.kind;
    switch (request.kind) {
    case service::RequestKind::advertisementUpdate:
        return state::matchmaking::prepare_variant_update(context,
                                                          request.advertisement.existingId,
                                                          request.advertisement.variantKey,
                                                          request.advertisement.hasDescriptor,
                                                          request.advertisement.descriptor,
                                                          response.advertisementId,
                                                          mutation);
    case service::RequestKind::rejoinAdvertisementUpdate:
        return state::matchmaking::prepare_initial_latest(
            context, response.advertisementId, mutation);
    case service::RequestKind::none:
    case service::RequestKind::sessionSearch:
    case service::RequestKind::advertisementDelete:
    case service::RequestKind::configuration:
    case service::RequestKind::rejoinAdvertisementDelete:
    case service::RequestKind::locateSession:
    case service::RequestKind::liveStats:
        return true;
    }
    return false;
}

} // namespace

/** Prepares and encodes one kind-specific svc-43 response transaction. */
bool encode_response(state::matchmaking::ContextHandle context,
                     std::span<const std::byte> requestBody,
                     std::span<std::byte> output,
                     std::size_t& written,
                     state::matchmaking::PendingMutation& mutation,
                     bool& hasMutation) noexcept {
    written = 0;
    hasMutation = false;
    SecureZeroMemory(&mutation, sizeof mutation);
    const service::Request request = service::request::parse(requestBody);
    service::Response response{};
    if (!prepare_fields(context, request, response, mutation)) {
        // A correlated empty fallback clears the pending client task without publishing State.
        SecureZeroMemory(&mutation, sizeof mutation);
        response = {};
    }

    state::matchmaking::LatestSnapshot latest{};
    if (response.kind == service::RequestKind::locateSession
        && state::matchmaking::latest_snapshot(context, latest)) {
        response.advertisementId = latest.advertisementId;
        if (latest.hasDescriptor) {
            response.descriptor = std::span(latest.descriptor);
        }
    }
    const bool encoded = service::response::encode(response, output, written);

    // No matchmaking line has ever appeared in a log, so an empty answer cannot be told from a
    // question that was never asked. Report both sides of the exchange once per request.
    {
        std::array<char, 160> line{};
        const int reported = std::snprintf(
            line.data(), line.size(),
            "ev=matchmaking stage=svc43 kind=%u req_bytes=%zu result=%s bytes=%zu",
            static_cast<unsigned>(request.kind),
            requestBody.size(),
            encoded ? "ok" : "fail",
            written);
        if (reported > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(reported)});
        }
    }
    state::matchmaking::erase_snapshot(latest);
    if (!encoded) {
        written = 0;
        SecureZeroMemory(&mutation, sizeof mutation);
        return false;
    }
    hasMutation = mutation.kind != state::matchmaking::MutationKind::none;
    return true;
}

} // namespace sunrise::server::bap::encrypted::matchmaking
