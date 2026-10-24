#pragma once

#include "e2e.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Clipboard pictures, the machine's side: the PNG hawk-capture reads off
// the clipboard goes to viewers, and a viewer's goes onto it, under the
// same rules as text (ClipboardConfig, ViewerHub's role checks) and only
// while `clipboard.images` is on.
//
// A picture is up to 8 MB, far more than text, so it doesn't travel as one
// clipboard message: it goes in 64 KB chunks over ViewerHub's image
// channel, which the relay queues with file data (behind input, events and
// the picture), with only a small window unacknowledged either way. One
// large copy then never holds up input or video for longer than a chunk
// takes. Each message is an op, a JSON header and (for chunks) PNG bytes:
//
//   viewer -> machine                      machine -> viewer
//   hello    {}                            image    {id, offset, size, pushed} + data
//   ack      {id, received}                skipped  {pushed}   one too large to send
//   cancel   {id}                          progress {id, received}
//   chunk    {id, offset, size} + data     done     {id}       it's on the clipboard
//                                          error    {id, message}
//
// Only `image` (the chunks) goes over the image channel itself. The small
// answers go sealed on the reply key (ViewerHub::send_clipboard_image_reply),
// which the relay passes with its events and never drops: a lost `done`
// would report a paste failed that went through.
//
// A dashboard says hello once admitted, so pictures only ever go to one
// that can take them; to any other, a clipboard holding only a picture
// reads as empty, as it always did. `chunk` is sealed apart from the rest
// (ViewerHub::clipboard_image_put), so the relay can hold it to control.
namespace hawk::service {

namespace image_op {
inline constexpr std::uint8_t hello = 1;
inline constexpr std::uint8_t ack = 2;
inline constexpr std::uint8_t cancel = 3;
inline constexpr std::uint8_t chunk = 4;

inline constexpr std::uint8_t image = 17;
inline constexpr std::uint8_t skipped = 18;
inline constexpr std::uint8_t progress = 19;
inline constexpr std::uint8_t done = 20;
inline constexpr std::uint8_t error = 21;
}  // namespace image_op

// A picture a viewer finished pasting, for hawk-capture to put on the
// clipboard.
struct PastedImage {
    std::string id;
    std::string png;
};

// Thread-safety: every method may be called from any thread; chunks are
// sent from an internal worker thread, which also drops pastes a viewer
// stopped sending, and answers go through `hub`. Destroy this before the hub.
class ClipboardImages {
public:
    explicit ClipboardImages(ViewerHub& hub);
    ~ClipboardImages();
    ClipboardImages(const ClipboardImages&) = delete;
    ClipboardImages& operator=(const ClipboardImages&) = delete;
    ClipboardImages(ClipboardImages&&) = delete;
    ClipboardImages& operator=(ClipboardImages&&) = delete;

    // A picture off the clipboard (ViewerHub::deliver_clipboard_image says
    // for whom), as PNG; empty for one too large to send, which they're
    // told instead. A newer one for a viewer replaces one still going.
    void send(std::vector<std::uint64_t> viewers, std::string_view png, bool pushed);

    // An ack or cancel the hub opened for this viewer. A cancel also drops
    // a paste of that id this viewer was sending.
    void handle(std::uint64_t viewer, ChannelMessage message);

    // A chunk of a picture this viewer is pasting, opened by the hub: the
    // whole PNG once its last chunk is in and it's a picture within the
    // limits. Progress and refusals are answered here.
    [[nodiscard]] std::optional<PastedImage> receive(std::uint64_t viewer, const ChannelMessage& message);

    // Tells the viewer whether its picture went on the clipboard: an empty
    // `error` for yes.
    void finished(std::uint64_t viewer, const std::string& id, std::string_view error);

    // A chunk the hub opened but the viewer may not send: tells it why,
    // so its paste fails at once rather than waiting.
    void refuse(std::uint64_t viewer, const ChannelMessage& message, const std::string& reason);

    // The viewer stopped watching: what was going either way stops.
    void drop_viewer(std::uint64_t viewer);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::service
