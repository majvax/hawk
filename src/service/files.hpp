#pragma once

#include "config.hpp"
#include "e2e.hpp"

#include <cstdint>
#include <memory>

// File transfer, the machine's side: viewers with control send files into
// one drop directory, and fetch files from it. Nothing outside that
// directory is ever named, listed, read or written, and every file
// operation runs as the logged-on user (impersonated), so a viewer gets
// exactly that user's rights there and no more: the service's own SYSTEM
// rights never touch a path the user could redirect.
//
// The messages travel over ViewerHub's file channel, end-to-end encrypted.
// Each one is an op, a JSON header and (for chunks) file data:
//
//   viewer -> machine                      machine -> viewer
//   list    {}                             listing  {dir, files: [{name, size, modified}]}
//   offer   {id, name, size, sha256}       accepted {id, offset}   resume from here
//   chunk   {id, offset} + data            progress {id, received}
//   fetch   {id, name, offset}             done     {id, name}     saved under this name
//   ack     {id, received}                 meta     {id, size, sha256}
//   cancel  {id}                           data     {id, offset} + data
//                                          error    {id, message}
//
// Uploads are written to a hidden partial file named after their content
// hash and size, so one interrupted by a dropped connection picks up where
// it stopped when it's offered again; once complete and its SHA-256 checks
// out, it's renamed to its (sanitised, de-duplicated) name. Downloads are
// hashed first, then sent in a window of chunks the viewer acknowledges,
// so neither the relay nor the socket ever holds more than that window.
namespace hawk::service {

namespace file_op {
inline constexpr std::uint8_t list = 1;
inline constexpr std::uint8_t offer = 2;
inline constexpr std::uint8_t chunk = 3;
inline constexpr std::uint8_t fetch = 4;
inline constexpr std::uint8_t ack = 5;
inline constexpr std::uint8_t cancel = 6;

inline constexpr std::uint8_t listing = 17;
inline constexpr std::uint8_t accepted = 18;
inline constexpr std::uint8_t progress = 19;
inline constexpr std::uint8_t done = 20;
inline constexpr std::uint8_t meta = 21;
inline constexpr std::uint8_t data = 22;
inline constexpr std::uint8_t error = 23;
}  // namespace file_op

// Thread-safety: handle() and drop_viewer() may be called from any thread;
// the work happens on an internal worker thread, which answers through
// `hub`. Destroy this before the hub.
class FileTransfers {
public:
    FileTransfers(FilesConfig config, ViewerHub& hub);
    ~FileTransfers();
    FileTransfers(const FileTransfers&) = delete;
    FileTransfers& operator=(const FileTransfers&) = delete;
    FileTransfers(FileTransfers&&) = delete;
    FileTransfers& operator=(FileTransfers&&) = delete;

    // A message the hub opened for this viewer.
    void handle(std::uint64_t viewer, FileMessage message);

    // The viewer stopped watching: its transfers stop. An upload's partial
    // file is kept, so offering the same file again resumes it.
    void drop_viewer(std::uint64_t viewer);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::service
