import Foundation

public struct EatPassConfig: Sendable {
    public let attesterUrl: String
    public let issuerUrl: String
    public let issuerName: String
    public let originInfo: String
    public let ktLogPubHex: String?
    public let timeoutSeconds: TimeInterval
    public let teamId: String
    public let bundleId: String

    public init(
        attesterUrl: String,
        issuerUrl: String,
        issuerName: String = "issuer.eat-pass.dev",
        originInfo: String = "tool-gate.secure.build/v1/tools/email.send",
        ktLogPubHex: String? = nil,
        timeoutSeconds: TimeInterval = 30,
        teamId: String,
        bundleId: String
    ) {
        self.attesterUrl = attesterUrl
        self.issuerUrl = issuerUrl
        self.issuerName = issuerName
        self.originInfo = originInfo
        self.ktLogPubHex = ktLogPubHex
        self.timeoutSeconds = timeoutSeconds
        self.teamId = teamId
        self.bundleId = bundleId
    }
}

public struct MintResult: Sendable {
    public let authorizationHeader: String
    public let bindingHex: String
}

public enum EatPassError: Error, LocalizedError {
    case http(String)
    case attestation(String)
    case crypto(String)

    public var errorDescription: String? {
        switch self {
        case .http(let m), .attestation(let m), .crypto(let m): return m
        }
    }
}
