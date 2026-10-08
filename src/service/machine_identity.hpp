#pragma once

#include <optional>
#include <string>
#include <vector>

namespace hawk::service {

// Which machine this PC enrolled as, and the name of the key (see
// MachineKey) it proves that with. Neither is secret: the secret is the
// private key, which never leaves the TPM. Kept in
// C:\ProgramData\HawkService\machine.txt.
struct MachineIdentity {
    std::string  machine_id;  // assigned by the relay at enrollment
    std::wstring key_name;    // the persisted CNG key's name
};

[[nodiscard]] std::optional<MachineIdentity> load_machine_identity();
[[nodiscard]] bool                           save_machine_identity(const MachineIdentity& identity);

// A fresh, unique key name for an enrollment attempt, so a failed attempt
// never touches the key of the identity already in place.
[[nodiscard]] std::wstring new_machine_key_name();

// The one-time enrollment code from the owner's dashboard, dropped in place
// by install-service.ps1 -EnrollCode. While it exists it takes precedence
// over the stored identity, so re-enrolling a machine is just installing a
// new code. Deleted once the enrollment goes through.
[[nodiscard]] std::optional<std::string> load_enroll_code();
void                                     delete_enroll_code();

// Removes the bearer credential that machines enrolled before key-based
// authentication kept; it's no longer accepted by the relay.
void delete_legacy_credential();

// The relay TLS keys this machine accepts (base64 SHA-256 of the SPKI, one
// per line), written by install-service.ps1 -RelayPin. Empty means pinning
// is off and only the normal certificate chain check applies.
[[nodiscard]] std::vector<std::string> load_relay_pins();

}  // namespace hawk::service
