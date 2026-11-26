param([ValidateSet('list','capture','regions')][string]$Mode)
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
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class KovanDiagnosticDump {
    [StructLayout(LayoutKind.Sequential)]
    struct MemoryInformation {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public int Alignment;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public sealed class Region {
        public string address { get; set; }
        public ulong size { get; set; }
        public string type { get; set; }
        public string protection { get; set; }
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder name, ref int length);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern UIntPtr VirtualQueryEx(SafeProcessHandle process, IntPtr address, out MemoryInformation info, UIntPtr length);
    [DllImport("dbghelp.dll", SetLastError=true)]
    static extern bool MiniDumpWriteDump(SafeProcessHandle process, int id, SafeFileHandle file, uint flags, IntPtr exception, IntPtr streams, IntPtr callback);

    static void Verify(SafeProcessHandle process, long expectedStart, string expectedImage) {
        if (process.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        int length = 32768;
        var image = new StringBuilder(length);
        long created, exited, kernel, user;
        if (!QueryFullProcessImageName(process, 0, image, ref length) ||
            !GetProcessTimes(process, out created, out exited, out kernel, out user)) throw new Win32Exception();
        if (exited != 0 || created != expectedStart || !String.Equals(expectedImage, image.ToString(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Process changed. Refresh the process list.");
    }

    public static Region[] FindRegions(int id, long expectedStart, string expectedImage) {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("64-bit Windows PowerShell required.");
        using (var process = OpenProcess(0x0400, false, id)) {
            Verify(process, expectedStart, expectedImage);
            var results = new List<Region>();
            var length = (UIntPtr)Marshal.SizeOf(typeof(MemoryInformation));
            long address = 0;
            while (true) {
                MemoryInformation info;
                var returned = VirtualQueryEx(process, new IntPtr(address), out info, length);
                if (returned == UIntPtr.Zero) {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 87 && address != 0) break; // End of the user-mode address space.
                    throw new Win32Exception(error);
                }
                long start = info.BaseAddress.ToInt64();
                long next = checked(start + (long)info.RegionSize.ToUInt64());
                if (next <= address) throw new InvalidOperationException("Invalid memory region size.");
                address = next;
                uint protection = info.Protect & 0xff;
                if (info.State != 0x1000 || (info.Type != 0x20000 && info.Type != 0x40000) ||
                    (protection != 0x10 && protection != 0x20 && protection != 0x40 && protection != 0x80)) continue;
                string access = protection == 0x10 ? "X" : protection == 0x20 ? "RX" : protection == 0x40 ? "RWX" : "RX/COW";
                results.Add(new Region {
                    address = "0x" + start.ToString("X"),
                    size = info.RegionSize.ToUInt64(),
                    type = info.Type == 0x20000 ? "MEM_PRIVATE" : "MEM_MAPPED",
                    protection = access + ((info.Protect & 0x100) != 0 ? " + GUARD" : "")
                });
                if (results.Count == 500) break;
            }
            Verify(process, expectedStart, expectedImage);
            return results.ToArray();
        }
    }

    public static void Capture(int id, long expectedStart, string expectedImage, string output) {
        using (var process = OpenProcess(0x0410, false, id)) {
            Verify(process, expectedStart, expectedImage);
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
    if ($Mode -eq 'regions') {
        $regions = [KovanDiagnosticDump]::FindRegions([int]$env:KOVAN_DUMP_PID, [long]$env:KOVAN_DUMP_STARTED, $exePath)
        ConvertTo-Json -InputObject $regions -Compress
        return
    }
    [KovanDiagnosticDump]::Capture([int]$env:KOVAN_DUMP_PID, [long]$env:KOVAN_DUMP_STARTED, $exePath, $env:KOVAN_DUMP_TEMP)
} catch {
    [Console]::Error.WriteLine($_.Exception.GetBaseException().Message)
    exit 1
}
