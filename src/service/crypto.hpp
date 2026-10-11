#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The primitives end-to-end encryption is built from, over Windows CNG
// (bcrypt): SHA-256, HMAC, HKDF, AES-256-GCM, ECDSA P-256 verification and
// ECDH P-256. Keys and signatures use the same encodings as the browser's
// WebCrypto and the relay: uncompressed points (0x04 || X || Y) and r || s.
//
// Like the rest of the service's interfaces, no Windows type crosses this
// one.
namespace hawk::crypto {

using Bytes = std::vector<std::byte>;
inline constexpr std::size_t sha256_size = 32;
using Sha256Digest = std::array<std::byte, sha256_size>;

inline constexpr std::size_t public_key_size = 65;
inline constexpr std::size_t aes_key_size = 32;
inline constexpr std::size_t gcm_iv_size = 12;
inline constexpr std::size_t gcm_tag_size = 16;

[[nodiscard]] Bytes as_bytes(std::string_view text);
[[nodiscard]] std::string base64_encode(std::span<const std::byte> data);
[[nodiscard]] std::optional<Bytes> base64_decode(std::string_view text);

// Fills `out` from the system RNG.
void random(std::span<std::byte> out);

[[nodiscard]] Sha256Digest sha256(std::span<const std::byte> data);
[[nodiscard]] Sha256Digest hmac_sha256(std::span<const std::byte> key, std::span<const std::byte> data);
// RFC 5869 with SHA-256; `length` at most 255 * 32.
[[nodiscard]] Bytes hkdf_sha256(std::span<const std::byte> ikm, std::span<const std::byte> salt, std::string_view info,
                                std::size_t length);

// Equal without leaking where they differ through timing.
[[nodiscard]] bool equal(std::span<const std::byte> lhs, std::span<const std::byte> rhs);

[[nodiscard]] bool is_public_key(std::span<const std::byte> key);

// ECDSA P-256 over SHA-256(message), signature as r || s.
[[nodiscard]] bool ecdsa_verify(std::span<const std::byte> public_key, std::span<const std::byte> message,
                                std::span<const std::byte> signature);

// An AES-256-GCM key. Not safe to use from two threads at once.
class AesGcm {
public:
    // nullopt unless `key` is 32 bytes and CNG accepts it.
    [[nodiscard]] static std::optional<AesGcm> create(std::span<const std::byte> key);

    AesGcm(AesGcm&&) noexcept;
    AesGcm& operator=(AesGcm&&) noexcept;
    AesGcm(const AesGcm&) = delete;
    AesGcm& operator=(const AesGcm&) = delete;
    ~AesGcm();

    // ciphertext || tag.
    [[nodiscard]] Bytes encrypt(std::span<const std::byte> nonce, std::span<const std::byte> plaintext,
                                std::span<const std::byte> aad) const;
    // nullopt when the tag doesn't verify.
    [[nodiscard]] std::optional<Bytes> decrypt(std::span<const std::byte> nonce, std::span<const std::byte> sealed,
                                               std::span<const std::byte> aad) const;

private:
    struct Impl;
    explicit AesGcm(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

// A one-off ECDH P-256 key pair, for one viewer's key exchange.
class ExchangeKey {
public:
    [[nodiscard]] static std::optional<ExchangeKey> generate();

    ExchangeKey(ExchangeKey&&) noexcept;
    ExchangeKey& operator=(ExchangeKey&&) noexcept;
    ExchangeKey(const ExchangeKey&) = delete;
    ExchangeKey& operator=(const ExchangeKey&) = delete;
    ~ExchangeKey();

    [[nodiscard]] const Bytes& public_key() const noexcept;
    // The shared point's x coordinate (32 bytes, big-endian, as WebCrypto's
    // deriveBits gives it), or nullopt if `peer` isn't a valid point.
    [[nodiscard]] std::optional<Bytes> agree(std::span<const std::byte> peer) const;

private:
    struct Impl;
    explicit ExchangeKey(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::crypto
