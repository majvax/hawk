#pragma once

#include <memory>
#include <string>

namespace hawk::capture {

// Reads and writes this session's clipboard for hawk-service, over the
// clipboard pipe (see common/clipboard_pipe.hpp): text set by a viewer is
// put on it, a viewer's request to read it is answered, and with `listen`
// every copy made on the machine is reported as it happens.
//
// The clipboard API needs a window, and a thread that owns a window can't
// move to another desktop, so the clipboard has a thread of its own that
// stays on the session's default desktop, where the clipboard's window
// station is, whichever desktop the capture and input threads follow. Pipe
// reads happen on a second thread, which hands requests to the window.
//
// Text (CF_UNICODETEXT) is passed as UTF-8 and capped at
// ipc::max_clipboard_size. With `images`, a picture is too, as PNG (see
// clipboard_image.hpp): one set by a viewer goes on as PNG, CF_DIBV5 and
// CF_DIB, and one read here goes out when the clipboard holds no text.
// Pictures past ipc::max_clipboard_image_size (or its size in pixels) are
// reported as too large, never cut.
class ClipboardChannel {
public:
    ClipboardChannel();
    ~ClipboardChannel();

    ClipboardChannel(const ClipboardChannel&) = delete;
    ClipboardChannel& operator=(const ClipboardChannel&) = delete;
    ClipboardChannel(ClipboardChannel&&) = delete;
    ClipboardChannel& operator=(ClipboardChannel&&) = delete;

    // Opens hawk-service's end of the pipe and starts serving it. Failures
    // are logged; the clipboard simply stays unavailable.
    [[nodiscard]] bool open(const std::string& pipe_name, bool listen, bool images);

    // Stops both threads. Safe to call when the channel was never opened.
    void close() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::capture
