using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EatPass.Desktop;

/// <summary>
/// TPM2 bundle collection via collect-desktop-tpm-windows.ps1 (tpm2-tools on PATH).
/// </summary>
public static class TpmAttestation
{
    public static async Task<string> CollectBundleJsonAsync(
        EatPassConfig config,
        string bindingHex,
        CancellationToken ct = default)
    {
        var script = config.CollectScriptPath ?? FindRepoScript();
        if (script is null || !File.Exists(script))
        {
            throw new EatPassException(
                "collect-desktop-tpm-windows.ps1 not found; set CollectScriptPath on EatPassConfig");
        }

        var psi = new ProcessStartInfo
        {
            FileName = "powershell",
            ArgumentList =
            {
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script,
                "-OutFile",
                "-",
            },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.Environment["BINDING"] = bindingHex.Trim();
        psi.Environment["BUILD_DIGEST"] = config.BuildDigestHex.Trim();

        using var proc = Process.Start(psi)
            ?? throw new EatPassException("failed to start PowerShell collect script");
        var stdout = await proc.StandardOutput.ReadToEndAsync(ct);
        var stderr = await proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);
        if (proc.ExitCode != 0)
        {
            throw new EatPassException(
                $"TPM collect failed ({proc.ExitCode}): {stderr}{stdout}");
        }

        var text = stdout.Trim();
        if (!text.StartsWith('{'))
        {
            throw new EatPassException("TPM collect script did not return JSON on stdout");
        }
        JsonDocument.Parse(text);
        return text;
    }

    /// <summary>Domain-separated build id for policy allow[].measurement.</summary>
    public static string DesktopBuildIdHashHex(string buildDigestHex)
    {
        var digest = ParseHex32(buildDigestHex, "buildDigest");
        var domain = Encoding.UTF8.GetBytes("uq/desktop/build-id/v1\u0000");
        var hash = SHA256.HashData(Concat(domain, digest));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? FindRepoScript()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8; i++)
        {
            var candidate = Path.Combine(dir, "scripts", "collect-desktop-tpm-windows.ps1");
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetFullPath(Path.Combine(dir, ".."));
        }
        return null;
    }

    private static byte[] ParseHex32(string hex, string field)
    {
        hex = hex.Trim();
        if (hex.Length != 64) throw new EatPassException($"{field} must be 64 hex chars");
        return Convert.FromHexString(hex);
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var outBuf = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, outBuf, 0, a.Length);
        Buffer.BlockCopy(b, 0, outBuf, a.Length, b.Length);
        return outBuf;
    }
}
