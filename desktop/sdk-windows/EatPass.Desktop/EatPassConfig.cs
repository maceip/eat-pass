namespace EatPass.Desktop;

public sealed class EatPassConfig
{
    public required string AttesterUrl { get; init; }
    public required string IssuerUrl { get; init; }
    public string IssuerName { get; init; } = "issuer.eat-pass.dev";
    public string OriginInfo { get; init; } = "tool-gate.secure.build/v1/tools/email.send";
    public string? KtLogPubHex { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>sha256(agent binary) hex — required for TPM mint.</summary>
    public required string BuildDigestHex { get; init; }
    /// <summary>Optional override to collect-desktop-tpm-windows.ps1</summary>
    public string? CollectScriptPath { get; init; }
}

public sealed record MintResult(string AuthorizationHeader, string BindingHex);

public sealed class EatPassException : Exception
{
    public EatPassException(string message) : base(message) { }
    public EatPassException(string message, Exception inner) : base(message, inner) { }
}
