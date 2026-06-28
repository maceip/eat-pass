using System.Diagnostics;
using System.Text.Json;

namespace EatPass.Desktop;

/// <summary>
/// PoMFRIT crypto via long-lived <c>eat-pass-mobile-ffi</c> subprocess (stdio JSON).
/// Set <see cref="BinaryPath"/> or <c>EAT_PASS_MOBILE_FFI</c> env var to override.
/// </summary>
public sealed class EatPassNative : IDisposable
{
    public static string? BinaryPath { get; set; }

    private readonly Process _proc;
    private readonly StreamWriter _stdin;
    private readonly StreamReader _stdout;
    private readonly object _lock = new();
    private bool _disposed;

    public EatPassNative()
    {
        var bin = BinaryPath
            ?? Environment.GetEnvironmentVariable("EAT_PASS_MOBILE_FFI")
            ?? "eat-pass-mobile-ffi";
        var psi = new ProcessStartInfo
        {
            FileName = bin,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        _proc = Process.Start(psi) ?? throw new EatPassException($"failed to start {bin}");
        _stdin = _proc.StandardInput;
        _stdout = _proc.StandardOutput;
    }

    public NativeClient CreateClient(string issuerPkJson, string issuerName, string originInfo)
    {
        var resp = Rpc(new
        {
            op = "new",
            issuer_pk_json = issuerPkJson,
            issuer_name = issuerName,
            origin_info = originInfo,
        });
        var id = resp.GetProperty("id").GetUInt64();
        return new NativeClient(this, id);
    }

    internal void Drop(ulong sessionId)
    {
        Rpc(new { op = "drop", id = sessionId });
    }

    internal BeginResult Begin(ulong sessionId, uint count)
    {
        var resp = Rpc(new { op = "begin", id = sessionId, count });
        return new BeginResult(
            resp.GetProperty("request_json").GetString()!,
            resp.GetProperty("binding_hex").GetString()!);
    }

    internal string Finalize(ulong sessionId, string signResponseJson)
    {
        var resp = Rpc(new
        {
            op = "finalize",
            id = sessionId,
            sign_response_json = signResponseJson,
        });
        return resp.GetProperty("authorization_header").GetString()
            ?? throw new EatPassException("issuer returned no token");
    }

    private JsonElement Rpc(object payload)
    {
        lock (_lock)
        {
            var line = JsonSerializer.Serialize(payload);
            _stdin.WriteLine(line);
            _stdin.Flush();
            var outLine = _stdout.ReadLine()
                ?? throw new EatPassException("eat-pass-mobile-ffi closed stdout");
            using var doc = JsonDocument.Parse(outLine);
            var root = doc.RootElement;
            if (!root.GetProperty("ok").GetBoolean())
            {
                throw new EatPassException(root.GetProperty("error").GetString() ?? "ffi error");
            }
            return root.GetProperty("result").Clone();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _stdin.Dispose();
        _stdout.Dispose();
        if (!_proc.HasExited)
        {
            _proc.Kill(entireProcessTree: true);
        }
        _proc.Dispose();
    }

    public sealed class NativeClient : IDisposable
    {
        private readonly EatPassNative _parent;
        private readonly ulong _id;
        private bool _disposed;

        internal NativeClient(EatPassNative parent, ulong id)
        {
            _parent = parent;
            _id = id;
        }

        public BeginResult Begin(uint count) => _parent.Begin(_id, count);

        public string Finalize(string signResponseJson) =>
            _parent.Finalize(_id, signResponseJson);

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                _parent.Drop(_id);
            }
            catch
            {
                // best effort
            }
        }
    }

    public sealed record BeginResult(string RequestJson, string BindingHex);
}
