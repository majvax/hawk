#include "clipboard_images.hpp"

#include "common/clipboard_pipe.hpp"

#include <glaze/glaze.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <format>
#include <map>
#include <mutex>
#include <span>
#include <thread>
#include <utility>
#include <variant>

namespace hawk::service {

namespace {

// What one chunk carries, and how many may be unacknowledged at once: a
// quarter megabyte in flight, half what a file transfer allows, so input
// sent behind a pasted picture waits for no more than that.
constexpr std::size_t kChunkSize = 64 * 1024;
constexpr std::size_t kWindowChunks = 4;
// A picture whose viewer stopped acknowledging is given up on; one a
// viewer stopped sending is dropped.
constexpr auto kSendTimeout = std::chrono::seconds(20);
constexpr auto kReceiveTimeout = std::chrono::seconds(30);
constexpr std::size_t kMaxIdLength = 40;

using Clock = std::chrono::steady_clock;

struct RequestHeader {
    std::string   id;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint64_t received = 0;
};

struct ReplyHeader {
    std::string                  id;
    std::optional<std::uint64_t> offset{};
    std::optional<std::uint64_t> size{};
    std::optional<std::uint64_t> received{};
    std::optional<bool>          pushed{};
    std::optional<std::string>   message{};
};

struct SkippedHeader {
    bool pushed = false;
};

}  // namespace

}  // namespace hawk::service

template <>
struct glz::meta<hawk::service::RequestHeader> {
    using T                     = hawk::service::RequestHeader;
    static constexpr auto value =
        object("id", &T::id, "offset", &T::offset, "size", &T::size, "received", &T::received);
};

template <>
struct glz::meta<hawk::service::ReplyHeader> {
    using T                     = hawk::service::ReplyHeader;
    static constexpr auto value = object("id", &T::id, "offset", &T::offset, "size", &T::size, "received",
                                         &T::received, "pushed", &T::pushed, "message", &T::message);
};

template <>
struct glz::meta<hawk::service::SkippedHeader> {
    using T                     = hawk::service::SkippedHeader;
    static constexpr auto value = object("pushed", &T::pushed);
};

namespace hawk::service {

namespace {

template <typename Header>
[[nodiscard]] std::string to_json(const Header& header) {
    auto json = glz::write_json(header);
    return json.has_value() ? *json : std::string{};
}

[[nodiscard]] bool is_valid_id(std::string_view id) {
    return !id.empty() && id.size() <= kMaxIdLength && std::ranges::all_of(id, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
    });
}

// A picture on its way to one viewer.
struct Outgoing {
    std::string                        id;
    std::shared_ptr<const std::string> png;
    bool                               pushed = false;
    std::uint64_t                      sent = 0;
    std::uint64_t                      acked = 0;
    Clock::time_point                  last_ack = Clock::now();
};

// One a viewer is pasting.
struct Incoming {
    std::string       id;
    std::uint64_t     size = 0;
    std::string       png;
    Clock::time_point last_chunk = Clock::now();
};

struct Picture {
    std::vector<std::uint64_t>         viewers;
    std::shared_ptr<const std::string> png;
    bool                               pushed = false;
};

struct Request {
    std::uint64_t  viewer = 0;
    ChannelMessage message;
};

struct Drop {
    std::uint64_t viewer = 0;
};

}  // namespace

struct ClipboardImages::Impl {
    ViewerHub& hub;

    std::mutex                                       mutex;
    std::condition_variable                          wake;
    std::deque<std::variant<Picture, Request, Drop>> queue;
    bool                                             stopping = false;

    // Worker thread only.
    std::map<std::uint64_t, Outgoing> outgoing;
    std::uint64_t                     next_id = 0;

    // Pastes coming in: the relay thread adds to them, the worker drops the
    // ones a viewer stopped sending, so an abandoned one isn't held.
    std::mutex                        incoming_mutex;
    std::map<std::uint64_t, Incoming> incoming;

    std::jthread worker;

    explicit Impl(ViewerHub& viewer_hub) : hub(viewer_hub) {
        worker = std::jthread([this] { run(); });
    }

    ~Impl() {
        {
            const std::lock_guard lock(mutex);
            stopping = true;
        }
        wake.notify_all();
        worker.join();
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    void push(std::variant<Picture, Request, Drop> event) {
        {
            const std::lock_guard lock(mutex);
            queue.push_back(std::move(event));
        }
        wake.notify_one();
    }

    void run() {
        for (;;) {
            std::deque<std::variant<Picture, Request, Drop>> events;
            {
                std::unique_lock lock(mutex);
                // Acks come through the queue; the timeout is only for
                // noticing a viewer that stopped sending them, or chunks.
                wake.wait_for(lock, std::chrono::seconds(1), [this] { return stopping || !queue.empty(); });
                if (stopping) {
                    break;
                }
                std::swap(events, queue);
            }
            for (auto& event : events) {
                if (auto* picture = std::get_if<Picture>(&event)) {
                    start(*picture);
                } else if (auto* request = std::get_if<Request>(&event)) {
                    serve(request->viewer, request->message);
                } else {
                    outgoing.erase(std::get<Drop>(event).viewer);
                }
            }
            pump();
            expire();
        }
        outgoing.clear();
    }

    void reply(std::uint64_t viewer, std::uint8_t op, const auto& header) {
        hub.send_clipboard_image_reply(viewer, {.op = op, .header = to_json(header), .data = {}});
    }

    // --- machine -> viewer (worker thread) ---------------------------------------

    void start(const Picture& picture) {
        for (const auto viewer : picture.viewers) {
            if (picture.png->empty()) {
                // Too large: whatever was still going is old news too.
                outgoing.erase(viewer);
                reply(viewer, image_op::skipped, SkippedHeader{.pushed = picture.pushed});
                continue;
            }
            outgoing.insert_or_assign(viewer, Outgoing{.id = std::format("{}", ++next_id),
                                                       .png = picture.png,
                                                       .pushed = picture.pushed,
                                                       .sent = 0,
                                                       .acked = 0,
                                                       .last_ack = Clock::now()});
        }
    }

    void serve(std::uint64_t viewer, const ChannelMessage& message) {
        RequestHeader header;
        if (glz::read<glz::opts{.error_on_unknown_keys = false}>(header, message.header)) {
            return;
        }
        const auto found = outgoing.find(viewer);
        if (found == outgoing.end() || found->second.id != header.id) {
            return;  // one replaced or given up on since
        }
        Outgoing& picture = found->second;
        if (message.op == image_op::cancel) {
            outgoing.erase(found);
        } else if (message.op == image_op::ack) {
            picture.acked = std::clamp(header.received, picture.acked, picture.sent);
            picture.last_ack = Clock::now();
            if (picture.acked == picture.png->size()) {
                outgoing.erase(found);
            }
        }
    }

    // Keeps every picture's window full.
    void pump() {
        for (auto it = outgoing.begin(); it != outgoing.end();) {
            auto& [viewer, picture] = *it;
            const auto size = picture.png->size();
            bool       gone = false;
            while (picture.sent < size && picture.sent - picture.acked < kWindowChunks * kChunkSize) {
                const auto length = std::min<std::uint64_t>(kChunkSize, size - picture.sent);
                const auto bytes = std::as_bytes(std::span(*picture.png).subspan(picture.sent, length));
                const ChannelMessage message{
                    .op = image_op::image,
                    .header = to_json(ReplyHeader{
                        .id = picture.id, .offset = picture.sent, .size = size, .pushed = picture.pushed}),
                    .data = {bytes.begin(), bytes.end()}};
                if (!hub.send_clipboard_image(viewer, message)) {
                    gone = true;
                    break;
                }
                picture.sent += length;
            }
            it = gone ? outgoing.erase(it) : std::next(it);
        }
    }

    void expire() {
        const auto now = Clock::now();
        {
            const std::lock_guard lock(incoming_mutex);
            std::erase_if(incoming, [now](const auto& entry) {
                if (now - entry.second.last_chunk > kReceiveTimeout) {
                    spdlog::info("clipboard: viewer {} stopped sending its picture; dropped it", entry.first);
                    return true;
                }
                return false;
            });
        }
        std::erase_if(outgoing, [now](const auto& entry) {
            const auto& picture = entry.second;
            if (picture.sent > picture.acked && now - picture.last_ack > kSendTimeout) {
                spdlog::info("clipboard: viewer {} stopped taking the picture; giving up on it", entry.first);
                return true;
            }
            return false;
        });
    }

    // --- viewer -> machine (relay thread) ------------------------------------------

    // Refuses one paste: drops it if it's the one this viewer is sending
    // (never another), and says why. Caller holds incoming_mutex.
    void refuse(std::uint64_t viewer, const std::string& id, std::string message) {
        spdlog::info("clipboard: refused viewer {}'s picture: {}", viewer, message);
        if (const auto found = incoming.find(viewer); found != incoming.end() && found->second.id == id) {
            incoming.erase(found);
        }
        reply(viewer, image_op::error, ReplyHeader{.id = id, .message = std::move(message)});
    }

    std::optional<PastedImage> receive(std::uint64_t viewer, const ChannelMessage& message) {
        RequestHeader header;
        if (message.op != image_op::chunk ||
            glz::read<glz::opts{.error_on_unknown_keys = false}>(header, message.header) || !is_valid_id(header.id)) {
            return std::nullopt;
        }
        const auto            now = Clock::now();
        const std::lock_guard lock(incoming_mutex);

        if (header.offset == 0) {
            if (header.size == 0 || header.size > ipc::max_clipboard_image_size) {
                refuse(viewer, header.id,
                       std::format("that's more than the {} MB of PNG the machine takes",
                                   ipc::max_clipboard_image_size / (1024 * 1024)));
                return std::nullopt;
            }
            // A new picture replaces one this viewer was still sending.
            Incoming picture{.id = header.id, .size = header.size, .png = {}, .last_chunk = now};
            picture.png.reserve(header.size);
            incoming.insert_or_assign(viewer, std::move(picture));
        }
        const auto found = incoming.find(viewer);
        // A leftover of a paste replaced since: the one going on is left be.
        if (found != incoming.end() && found->second.id != header.id) {
            return std::nullopt;
        }
        if (found == incoming.end() || found->second.size != header.size ||
            found->second.png.size() != header.offset || header.offset + message.data.size() > header.size) {
            refuse(viewer, header.id, "parts of the picture went missing; paste it again");
            return std::nullopt;
        }
        Incoming& picture = found->second;
        const auto* data = reinterpret_cast<const char*>(message.data.data());
        picture.png.append(data, message.data.size());
        picture.last_chunk = now;
        reply(viewer, image_op::progress, ReplyHeader{.id = picture.id, .received = picture.png.size()});
        if (picture.png.size() < picture.size) {
            return std::nullopt;
        }

        PastedImage pasted{.id = std::move(picture.id), .png = std::move(picture.png)};
        incoming.erase(found);
        const auto size = ipc::png_size(std::as_bytes(std::span(pasted.png)));
        if (!size.has_value() || !ipc::image_fits(*size)) {
            refuse(viewer, pasted.id,
                   size.has_value() ? std::format("a {}x{} picture is larger than the machine takes", size->width,
                                                  size->height)
                                    : "that isn't a PNG");
            return std::nullopt;
        }
        spdlog::info("clipboard: viewer {} ({}) pasted a {}x{} picture ({} bytes of PNG)", viewer,
                     hub.fingerprint_of(viewer), size->width, size->height, pasted.png.size());
        return pasted;
    }
};

ClipboardImages::ClipboardImages(ViewerHub& hub) : impl_(std::make_unique<Impl>(hub)) {}

ClipboardImages::~ClipboardImages() = default;

void ClipboardImages::send(std::vector<std::uint64_t> viewers, std::string_view png, bool pushed) {
    if (viewers.empty()) {
        return;
    }
    impl_->push(Picture{.viewers = std::move(viewers),
                        .png = std::make_shared<const std::string>(png),
                        .pushed = pushed});
}

void ClipboardImages::handle(std::uint64_t viewer, ChannelMessage message) {
    if (message.op == image_op::cancel) {
        RequestHeader header;
        if (!glz::read<glz::opts{.error_on_unknown_keys = false}>(header, message.header)) {
            const std::lock_guard lock(impl_->incoming_mutex);
            if (const auto found = impl_->incoming.find(viewer);
                found != impl_->incoming.end() && found->second.id == header.id) {
                impl_->incoming.erase(found);
            }
        }
    }
    impl_->push(Request{.viewer = viewer, .message = std::move(message)});
}

void ClipboardImages::refuse(std::uint64_t viewer, const ChannelMessage& message, const std::string& reason) {
    RequestHeader header;
    if (message.op != image_op::chunk ||
        glz::read<glz::opts{.error_on_unknown_keys = false}>(header, message.header) || !is_valid_id(header.id)) {
        return;
    }
    const std::lock_guard lock(impl_->incoming_mutex);
    impl_->refuse(viewer, header.id, reason);
}

std::optional<PastedImage> ClipboardImages::receive(std::uint64_t viewer, const ChannelMessage& message) {
    return impl_->receive(viewer, message);
}

void ClipboardImages::finished(std::uint64_t viewer, const std::string& id, std::string_view error) {
    if (error.empty()) {
        impl_->reply(viewer, image_op::done, ReplyHeader{.id = id});
    } else {
        impl_->reply(viewer, image_op::error, ReplyHeader{.id = id, .message = std::string(error)});
    }
}

void ClipboardImages::drop_viewer(std::uint64_t viewer) {
    {
        const std::lock_guard lock(impl_->incoming_mutex);
        impl_->incoming.erase(viewer);
    }
    impl_->push(Drop{.viewer = viewer});
}

}  // namespace hawk::service
