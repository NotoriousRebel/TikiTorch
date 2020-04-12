//
// Author: B4rtik (@b4rtik)
// Project: SharpMiniDump (https://github.com/b4rtik/SharpMiniDump)
// License: BSD 3-Clause
//

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using static TikiLoader.Natives;

namespace TikiLoader
{
    public class NativeSysCall
    {
        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x0f
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwClose10 = { 0x49, 0x89, 0xCA, 0xB8, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x3A
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwWriteVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x50
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwProtectVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x36
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwQuerySystemInformation10 = { 0x49, 0x89, 0xCA, 0xB8, 0x36, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x18
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bNtAllocateVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x1E
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bNtFreeVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x1E, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x55
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bNtCreateFile10 = { 0x49, 0x89, 0xCA, 0xB8, 0x55, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        ///0:  49 89 ca                mov r10,rcx
        ///3:  b8 26 00 00 00          mov eax,0x26
        ///8:  0f 05                   syscall
        ///a:  c3                      ret

        static byte[] bZwOpenProcess10 = { 0x49, 0x89, 0xCA, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        public static NTSTATUS ZwOpenProcess10(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
        {
            byte[] syscall = bZwOpenProcess10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwOpenProcess myAssemblyFunction = (Delegates.ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwOpenProcess));

                    return (NTSTATUS)myAssemblyFunction(out hProcess, processAccess, objAttribute, ref clientid);
                }
            }
        }

      

        public static NTSTATUS NtAllocateVirtualMemory10(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
        {
            byte[] syscall = bNtAllocateVirtualMemory10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtAllocateVirtualMemory myAssemblyFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
                }
            }
        }

        public static NTSTATUS NtFreeVirtualMemory10(IntPtr hProcess, ref IntPtr BaseAddress, ref uint RegionSize, ulong FreeType)
        {
            byte[] syscall = bNtFreeVirtualMemory10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtFreeVirtualMemory myAssemblyFunction = (Delegates.NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtFreeVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, ref BaseAddress, ref RegionSize, FreeType);
                }
            }
        }

        public static NTSTATUS ZwWriteVirtualMemory10(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
        {
            byte[] syscall = bZwWriteVirtualMemory10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwWriteVirtualMemory myAssemblyFunction = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwWriteVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
                }
            }
        }

        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwOpenProcess(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwClose(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwProtectVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, ulong FreeType);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlEqualUnicodeString(UNICODE_STRING String1, UNICODE_STRING String2, bool CaseInSensitive);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);


            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int LdrLoadDll(IntPtr PathToFile,
                UInt32 dwFlags,
                ref Natives.UNICODE_STRING ModuleFileName,
                ref IntPtr ModuleHandle);


            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RevertToSelf();

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr GetCurrentProcess();

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool CloseHandle(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint newprotect, out uint oldprotect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
            public delegate bool CreateProcessW(string lpApplicationName,
            string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref Structs.STARTUPINFOEX lpStartupInfo,
            out Structs.PROCESS_INFORMATION lpProcessInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate void GetSystemInfo(
                ref Structs.SYSTEM_INFO lpSysInfo
            );

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwMapViewOfSection(
               IntPtr section,
               IntPtr process,
               ref IntPtr baseAddr,
               IntPtr zeroBits,
               IntPtr commitSize,
               IntPtr stuff,
               ref IntPtr viewSize,
               int inheritDispo,
               Enums.AllocationType alloctype,
               Enums.MemoryProtection prot);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwCreateSection(
              ref IntPtr section,
              uint desiredAccess,
              IntPtr pAttrs,
              ref Structs.LARGE_INTEGER pMaxSize,
              Enums.MemoryProtection pageProt,
              Enums.AllocationType allocationAttribs,
              IntPtr hFile);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwQueryInformationProcess(
               IntPtr hProcess,
               int procInformationClass,
               ref Structs.PROCESS_BASIC_INFORMATION procInformation,
               uint ProcInfoLen,
               ref uint retlen);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool ReadProcessMemory(
               IntPtr hProcess,
               IntPtr lpBaseAddress,
               [Out] byte[] lpBuffer,
               int dwSize,
               out IntPtr lpNumberOfBytesRead);
           
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate uint ResumeThread(
                   IntPtr hThread);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwUnmapViewOfSection(
              IntPtr hSection,
              IntPtr address);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool DeleteProcThreadAttributeList(
               IntPtr lpAttributeList);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool WriteProcessMemory(
                IntPtr hProcess, 
                IntPtr lpBaseAddress, 
                IntPtr lpBuffer, 
                IntPtr nSize,
                out IntPtr lpNumWritten);
        }
    }
}
