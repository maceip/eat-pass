import DeviceCheck
import Foundation

/// Host-attested guest launcher (Gap C).
///
/// On a Mac there is no silicon root for a Linux VM's workload, so the macOS
/// host vouches for the guest. The flow is:
///
/// 1. `uq` (Rust) computes the guest agent's `value_x` over the VM image /
///    agent files, builds a software-witness guest EAT, and prints its CBOR
///    (`guestEatHex`) and its `binding_bytes()` (`guestBindingHex`).
/// 2. This launcher App-Attests the host with its channel binding committed to
///    `guestBindingHex`, tying a genuine Apple device + this launcher app to
///    exactly that guest image.
/// 3. It emits a `HostAttestedGuest` bundle (matching
///    `unified_quote::tee::desktop::host_guest::HostAttestedGuest`) for the gate.
///
/// The heavy lifting (value_x, EAT, binding) stays in the tested Rust core; this
/// is only the Apple App Attest step + JSON assembly.
public enum HostAttestedGuestLauncher {
    public static func createBundle(
        service: DCAppAttestService,
        keyId: String,
        credentialPublicKeyHex: String,
        teamId: String,
        bundleId: String,
        guestEatHex: String,
        guestBindingHex: String
    ) async throws -> Data {
        // App-Attest the host over the guest's binding (reuses the verified
        // MacOsAppAttest path; the verifier checks the binding equals the guest
        // EAT's binding_bytes()).
        let hostBundleData = try await MacOsAppAttest.createBundle(
            service: service,
            keyId: keyId,
            credentialPublicKeyHex: credentialPublicKeyHex,
            teamId: teamId,
            bundleId: bundleId,
            bindingHex: guestBindingHex
        )
        let host = try JSONSerialization.jsonObject(with: hostBundleData)

        let payload: [String: Any] = [
            "version": 1,
            "guest_eat": guestEatHex,
            "host": host,
        ]
        return try JSONSerialization.data(withJSONObject: payload)
    }
}
