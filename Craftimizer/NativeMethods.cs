using System;
using System.Runtime.InteropServices;
using System.Text;

public static class NativeMethods
{
    // The P/Invoke signature for VirtualQuery remains the same
    [DllImport("kernel32.dll")]
    public static extern int VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    // The struct remains the same
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    // Define all the memory constants we need for the test
    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOACCESS = 0x01;

    /// <summary>
    /// Performs the specific memory check requested by the maintainer.
    /// </summary>
    /// <param name="address">The pointer to check.</param>
    /// <returns>True if the memory is in a valid state according to the hypothesis.</returns>
    public static bool IsMemoryValid(IntPtr address)
    {
        // A null pointer is always invalid.
        if (address == IntPtr.Zero)
            return false;

        try
        {
            MEMORY_BASIC_INFORMATION buffer;
            var result = VirtualQuery(address, out buffer, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));

            // If the call fails, we can't trust the memory.
            if (result == 0)
                return false;

            // This is the maintainer's exact test:
            // 1. Is the memory state committed?
            bool isCommitted = buffer.State == MEM_COMMIT;
            // 2. Is the PAGE_GUARD flag NOT set in the protection flags?
            bool isNotGuard = (buffer.Protect & PAGE_GUARD) == 0;
            // 3. Is the PAGE_NOACCESS flag NOT set in the protection flags?
            bool isNotNoAccess = (buffer.Protect & PAGE_NOACCESS) == 0;

            return isCommitted && isNotGuard && isNotNoAccess;
        }
        catch
        {
            // If VirtualQuery itself fails for some reason, the address is bad.
            return false;
        }
    }
}
