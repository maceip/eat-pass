import DeviceCheck
import EatPassMobileRust
import Foundation

/// Coupled mint: macOS App Attest + attester + issuer + eat-pass finalize.
public final class EatPassDesktopClient: @unchecked Sendable {
    private let config: EatPassConfig
    private let appAttest: DCAppAttestService
    private let keyId: String
    private let credentialPublicKeyHex: String

    public init(
        config: EatPassConfig,
        appAttestService: DCAppAttestService = DCAppAttestService.shared,
        keyId: String,
        credentialPublicKeyHex: String
    ) {
        self.config = config
        self.appAttest = appAttestService
        self.keyId = keyId
        self.credentialPublicKeyHex = credentialPublicKeyHex
    }

    public func mintAuthorizationHeader() async throws -> MintResult {
        let issuerBase = config.issuerUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let attesterBase = config.attesterUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        let keysJson = try await httpGet("\(issuerBase)/keys")
        if let pin = config.ktLogPubHex {
            let ktJson = try await httpGet("\(issuerBase)/kt")
            let kt = try JSONSerialization.jsonObject(with: Data(ktJson.utf8)) as? [String: Any]
            let served = (kt?["log_pub"] as? String) ?? ""
            if served.lowercased() != pin.lowercased() {
                throw EatPassError.http("issuer KT log pubkey does not match pinned key")
            }
        }

        let crypto = try EatPassClient(
            issuerPkJson: keysJson,
            issuerName: config.issuerName,
            originInfo: config.originInfo
        )
        let begin = try crypto.begin(count: 1)
        let bundle = try await MacOsAppAttest.createBundle(
            service: appAttest,
            keyId: keyId,
            credentialPublicKeyHex: credentialPublicKeyHex,
            teamId: config.teamId,
            bundleId: config.bundleId,
            bindingHex: begin.bindingHex
        )
        let eatB64 = bundle.base64EncodedString()

        let authBody: [String: Any] = [
            "eat_b64": eatB64,
            "binding": begin.bindingHex,
            "max_batch": 1,
        ]
        let authResp = try await httpPost("\(attesterBase)/authorize", json: authBody)
        guard let authObj = try JSONSerialization.jsonObject(with: Data(authResp.utf8)) as? [String: Any],
              let authorizationB64 = authObj["authorization_b64"] as? String
        else {
            throw EatPassError.http("invalid /authorize response")
        }

        let reqObj = try JSONSerialization.jsonObject(with: Data(begin.requestJson.utf8))
        let signBody: [String: Any] = [
            "req": reqObj,
            "authorization_b64": authorizationB64,
        ]
        let signResp = try await httpPost("\(issuerBase)/sign", json: signBody)
        let headers = try crypto.finalize(signResponseJson: signResp)
        guard let first = headers.first else {
            throw EatPassError.crypto("issuer returned no token")
        }
        return MintResult(authorizationHeader: first, bindingHex: begin.bindingHex)
    }

    private func httpGet(_ url: String) async throws -> String {
        var req = URLRequest(url: URL(string: url)!)
        req.httpMethod = "GET"
        req.timeoutInterval = config.timeoutSeconds
        let (data, resp) = try await URLSession.shared.data(for: req)
        try throwIfHttpError(resp: resp, data: data, url: url)
        return String(decoding: data, as: UTF8.self)
    }

    private func httpPost(_ url: String, json: [String: Any]) async throws -> String {
        var req = URLRequest(url: URL(string: url)!)
        req.httpMethod = "POST"
        req.timeoutInterval = config.timeoutSeconds
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: json)
        let (data, resp) = try await URLSession.shared.data(for: req)
        try throwIfHttpError(resp: resp, data: data, url: url)
        return String(decoding: data, as: UTF8.self)
    }

    private func throwIfHttpError(resp: URLResponse, data: Data, url: String) throws {
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
            let body = String(decoding: data, as: UTF8.self)
            throw EatPassError.http("HTTP \(code) for \(url): \(body)")
        }
    }
}
