#pragma once

#include <optional>
#include <string>

namespace hawk::service {

// Persists how this machine proves itself to the relay.
//
// - The credential is issued by the relay when the machine enrolls. It is
//   stored encrypted with DPAPI under the service account's (SYSTEM's) own
//   key, so other accounts on this PC can't decrypt it even though they can
//   see the file.
// - The enrollment code is a one-time code from the owner's dashboard,
//   dropped in place by install-service.ps1 -EnrollCode. It is used once,
//   then deleted. While it exists it takes precedence over a stored
//   credential, so re-enrolling a machine is just installing a new code.
//
// Both live in C:\ProgramData\HawkService.

[[nodiscard]] std::optional<std::string> load_credential();
[[nodiscard]] bool                       save_credential(const std::string& credential);

[[nodiscard]] std::optional<std::string> load_enroll_code();
void                                     delete_enroll_code();

}  // namespace hawk::service
