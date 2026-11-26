param([ValidateSet('list','capture')][string]$Mode)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $exePath = [IO.Path]::GetFullPath($env:KOVAN_DUMP_IMAGE)
    $currentSession = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($Mode -eq 'list') {
        $rows = @(foreach ($candidate in [Diagnostics.Process]::GetProcessesByName([IO.Path]::GetFileNameWithoutExtension($exePath))) {
            try {
                if ($candidate.SessionId -eq $currentSession -and $candidate.MainModule.FileName -eq $exePath) {
                    [pscustomobject]@{ id = $candidate.Id; started = $candidate.StartTime.ToFileTimeUtc().ToString() }
                }
            } catch { continue } finally { $candidate.Dispose() }
        })
        ConvertTo-Json -InputObject $rows -Compress
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class KovanDiagnosticDump {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder name, ref int length);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
    [DllImport("dbghelp.dll", SetLastError=true)]
    static extern bool MiniDumpWriteDump(SafeProcessHandle process, int id, SafeFileHandle file, uint flags, IntPtr exception, IntPtr streams, IntPtr callback);

    public static void Capture(int id, long expectedStart, string expectedImage, string output) {
        using (var process = OpenProcess(0x0410, false, id)) {
            if (process.IsInvalid) throw new Win32Exception();
            int length = 32768;
            var image = new StringBuilder(length);
            long created, exited, kernel, user;
            if (!QueryFullProcessImageName(process, 0, image, ref length) ||
                !GetProcessTimes(process, out created, out exited, out kernel, out user)) throw new Win32Exception();
            if (exited != 0 || created != expectedStart || !String.Equals(expectedImage, image.ToString(), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Process changed. Refresh the process list.");
            using (var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                // Include thread information alongside normal stacks and loaded modules.
                if (!MiniDumpWriteDump(process, id, file.SafeFileHandle, 0x1000, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                file.Flush(true);
            }
        }
    }
}
'@
    [KovanDiagnosticDump]::Capture([int]$env:KOVAN_DUMP_PID, [long]$env:KOVAN_DUMP_STARTED, $exePath, $env:KOVAN_DUMP_TEMP)
} catch {
    [Console]::Error.WriteLine($_.Exception.GetBaseException().Message)
    exit 1
}
