import CryptoKit
import DeviceCheck
import Foundation

public enum IosAppAttest {
    public static func createBundle(
        service: DCAppAttestService,
        keyId: String,
        credentialPublicKeyHex: String,
        teamId: String,
        bundleId: String,
        bindingHex: String
    ) async throws -> Data {
        guard service.isSupported else {
            throw EatPassError.attestation("App Attest not supported")
        }
        let clientDataHash = iosClientDataHash(bindingHex: bindingHex)
        let assertion = try await generateAssertion(service: service, keyId: keyId, clientDataHash: clientDataHash)
        let payload: [String: Any] = [
            "version": 1,
            "platform": "ios-app-attest",
            "key_id": keyId,
            "assertion": assertion.base64EncodedString(),
            "credential_public_key": credentialPublicKeyHex,
            "team_id": teamId,
            "bundle_id": bundleId,
            "app_id_hash": appIdHash(teamId: teamId, bundleId: bundleId),
            "binding": bindingHex,
            "client_data_hash": clientDataHash.hexLower,
        ]
        return try JSONSerialization.data(withJSONObject: payload)
    }

    public static func appIdHash(teamId: String, bundleId: String) -> String {
        var msg = Data("uq/mobile/ios-app-id/v1\u{0}".utf8)
        msg.append(Data(teamId.utf8))
        msg.append(0)
        msg.append(Data(bundleId.utf8))
        return SHA256.hash(data: msg).hexLower
    }

    public static func iosClientDataHash(bindingHex: String) -> Data {
        let binding = Data(hex: bindingHex) ?? Data()
        var msg = Data("uq/mobile/ios/v1\u{0}".utf8)
        msg.append(binding)
        return Data(SHA256.hash(data: msg))
    }

    private static func generateAssertion(
        service: DCAppAttestService,
        keyId: String,
        clientDataHash: Data
    ) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            service.generateAssertion(keyId, clientDataHash: clientDataHash) { data, error in
                if let error {
                    cont.resume(throwing: EatPassError.attestation(error.localizedDescription))
                } else if let data {
                    cont.resume(returning: data)
                } else {
                    cont.resume(throwing: EatPassError.attestation("empty App Attest assertion"))
                }
            }
        }
    }
}

private extension SHA256.Digest {
    var hexLower: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

private extension Data {
    init?(hex: String) {
        let s = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.count % 2 == 0 else { return nil }
        var data = Data()
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let byte = UInt8(s[idx..<next], radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        self = data
    }

    var hexLower: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
