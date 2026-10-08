#pragma once

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hawk::service {

// The key this machine proves its identity to the relay with: ECDSA P-256,
// created inside the TPM through the Microsoft Platform Crypto Provider,
// non-exportable, so the private half never exists outside the chip. On a
// PC without a usable TPM it falls back to the software key storage
// provider's machine key store (still non-exportable, but only as strong as
// the OS protecting it); storage() says which.
//
// Keys are persisted under a name, in the machine (not user) key store, so
// the service finds them again after a restart.
//
// Like WebSocketClient, no Windows type crosses this interface.
class MachineKey {
public:
    // Creates a new persisted key named `name`.
    [[nodiscard]] static std::expected<MachineKey, std::string> create(const std::wstring& name);
    // Opens an existing key created by create().
    [[nodiscard]] static std::expected<MachineKey, std::string> open(const std::wstring& name);
    // Deletes a persisted key, wherever it lives. A missing key counts as
    // deleted; the error says what CNG refused otherwise.
    [[nodiscard]] static std::expected<void, std::string> destroy(const std::wstring& name);

    MachineKey(MachineKey&&) noexcept;
    MachineKey& operator=(MachineKey&&) noexcept;
    MachineKey(const MachineKey&) = delete;
    MachineKey& operator=(const MachineKey&) = delete;
    ~MachineKey();

    // "tpm" or "software".
    [[nodiscard]] std::string_view storage() const noexcept;

    // The public key as an uncompressed P-256 point: 0x04 || X || Y.
    [[nodiscard]] std::expected<std::vector<std::byte>, std::string> public_key() const;

    // ECDSA signature of SHA-256(message), as r || s (64 bytes).
    [[nodiscard]] std::expected<std::vector<std::byte>, std::string> sign(std::span<const std::byte> message) const;

private:
    struct Impl;
    explicit MachineKey(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::service
