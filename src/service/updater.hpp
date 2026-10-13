#pragma once

#include "config.hpp"

#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

// Keeps the machine up to date through hawk-setup.exe, installed beside the
// service. The service itself never downloads, verifies or replaces
// anything: hawk-setup checks the release feed's signature, stops this
// service, swaps the binaries, starts it again and rolls back if it doesn't
// come back. All the service does is ask it, on a timer and when the owner
// says so from the dashboard.
namespace hawk::service {

class Updater {
public:
    // Called from the updater's thread when what's available changes: a
    // release waiting for the owner, or nullopt.
    using Notify = std::function<void(const std::optional<std::string>& available)>;

    Updater(UpdateConfig config, Notify notify);
    ~Updater();

    Updater(const Updater&)            = delete;
    Updater& operator=(const Updater&) = delete;
    Updater(Updater&&)                 = delete;
    Updater& operator=(Updater&&)      = delete;

    // The owner asked for the update the machine is holding. Starts
    // hawk-setup on its own, which stops this service shortly after.
    void install_now();

    [[nodiscard]] std::optional<std::string> available() const;

private:
    void run(const std::stop_token& stop_token);
    void check(const std::stop_token& stop_token);

    UpdateConfig               config_;
    Notify                     notify_;
    mutable std::mutex         mutex_;
    std::optional<std::string> available_;
    std::jthread               thread_;
};

// hawk-setup.exe, next to this executable.
[[nodiscard]] std::filesystem::path setup_path();

}  // namespace hawk::service
