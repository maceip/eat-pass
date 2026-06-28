using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace EatPass.Desktop;

/// <summary>
/// Coupled mint for Windows agents: TPM attestation + attester + issuer + PoMFRIT finalize.
/// </summary>
public sealed class EatPassDesktopClient : IDisposable
{
    private readonly EatPassConfig _config;
    private readonly HttpClient _http;
    private readonly EatPassNative _native;
    private readonly bool _ownsNative;

    public EatPassDesktopClient(EatPassConfig config, HttpClient? http = null, EatPassNative? native = null)
    {
        _config = config;
        _http = http ?? new HttpClient { Timeout = config.Timeout };
        _native = native ?? new EatPassNative();
        _ownsNative = native is null;
    }

    public void Dispose()
    {
        _http.Dispose();
        if (_ownsNative)
        {
            _native.Dispose();
        }
    }

    public async Task<MintResult> MintAuthorizationHeaderAsync(CancellationToken ct = default)
    {
        var issuerBase = _config.IssuerUrl.TrimEnd('/');
        var attesterBase = _config.AttesterUrl.TrimEnd('/');

        var keysJson = await GetStringAsync($"{issuerBase}/keys", ct);
        if (_config.KtLogPubHex is { } pin)
        {
            var kt = await _http.GetFromJsonAsync<JsonElement>($"{issuerBase}/kt", ct);
            var served = kt.GetProperty("log_pub").GetString() ?? "";
            if (!string.Equals(served, pin, StringComparison.OrdinalIgnoreCase))
            {
                throw new EatPassException("issuer KT log pubkey does not match pinned key");
            }
        }

        using var client = _native.CreateClient(keysJson, _config.IssuerName, _config.OriginInfo);
        try
        {
            var begin = client.Begin(1);
        var bundleJson = await TpmAttestation.CollectBundleJsonAsync(_config, begin.BindingHex, ct);
        var eatB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(bundleJson));

        var authBody = new { eat_b64 = eatB64, binding = begin.BindingHex, max_batch = 1 };
        using var authResp = await _http.PostAsJsonAsync($"{attesterBase}/authorize", authBody, ct);
        authResp.EnsureSuccessStatusCode();
        var authJson = await authResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authorizationB64 = authJson.GetProperty("authorization_b64").GetString()
            ?? throw new EatPassException("missing authorization_b64");

        var signBody = new
        {
            req = JsonSerializer.Deserialize<JsonElement>(begin.RequestJson),
            authorization_b64 = authorizationB64,
        };
        using var signResp = await _http.PostAsJsonAsync($"{issuerBase}/sign", signBody, ct);
        signResp.EnsureSuccessStatusCode();
        var signJson = await signResp.Content.ReadAsStringAsync(ct);
        var header = client.Finalize(signJson);
        return new MintResult(header, begin.BindingHex);
        }
        finally
        {
            client.Dispose();
        }
    }

    private async Task<string> GetStringAsync(string url, CancellationToken ct)
    {
        using var resp = await _http.GetAsync(url, ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStringAsync(ct);
    }
}
