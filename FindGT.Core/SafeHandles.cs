using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FindGT
{
    /// <summary>Owns a kernel handle returned by Win32 or SSPI.</summary>
    internal sealed class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeKernelHandle()
            : base(true)
        {
        }

        internal SafeKernelHandle(IntPtr value)
            : base(true)
        {
            SetHandle(value);
        }

        protected override bool ReleaseHandle()
        {
            return Interop.CloseHandle(handle);
        }
    }

    internal sealed class SafeHGlobalBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeHGlobalBuffer()
            : base(true)
        {
        }

        private SafeHGlobalBuffer(IntPtr value)
            : base(true)
        {
            SetHandle(value);
        }

        internal static SafeHGlobalBuffer Allocate(int size)
        {
            if (size <= 0)
            {
                throw new ArgumentOutOfRangeException("size");
            }

            return new SafeHGlobalBuffer(Marshal.AllocHGlobal(size));
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal sealed class SafeLsaReturnBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeLsaReturnBuffer(IntPtr value)
            : base(true)
        {
            SetHandle(value);
        }

        protected override bool ReleaseHandle()
        {
            return Interop.LsaFreeReturnBuffer(handle) == 0;
        }
    }

    internal sealed class SafeLsaLogonProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeLsaLogonProcessHandle(IntPtr value)
            : base(true)
        {
            SetHandle(value);
        }

        protected override bool ReleaseHandle()
        {
            return Interop.LsaDeregisterLogonProcess(handle) == 0;
        }
    }

    internal sealed class SafeLsaPolicyHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeLsaPolicyHandle(IntPtr value)
            : base(true)
        {
            SetHandle(value);
        }

        protected override bool ReleaseHandle()
        {
            return Interop.LsaClose(handle) == 0;
        }
    }

    internal sealed class SafeLsaMemory : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeLsaMemory(IntPtr value)
            : base(true)
        {
            SetHandle(value);
        }

        protected override bool ReleaseHandle()
        {
            return Interop.LsaFreeMemory(handle) == 0;
        }
    }

    internal abstract class SafeSspiHandle : SafeHandle
    {
        private IntPtr _upper;

        protected SafeSspiHandle(Interop.SECURITY_HANDLE value)
            : base(IntPtr.Zero, true)
        {
            SetValue(value);
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero && _upper == IntPtr.Zero; }
        }

        internal Interop.SECURITY_HANDLE DangerousGetValue()
        {
            return new Interop.SECURITY_HANDLE
            {
                LowPart = handle,
                HighPart = _upper
            };
        }

        internal void SetValue(Interop.SECURITY_HANDLE value)
        {
            SetHandle(value.LowPart);
            _upper = value.HighPart;
        }

        protected void Clear()
        {
            SetHandle(IntPtr.Zero);
            _upper = IntPtr.Zero;
        }
    }

    internal sealed class SafeSspiCredentialHandle : SafeSspiHandle
    {
        internal SafeSspiCredentialHandle(Interop.SECURITY_HANDLE value)
            : base(value)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.SECURITY_HANDLE value = DangerousGetValue();
            uint status = Interop.FreeCredentialsHandle(ref value);
            Clear();
            return status == 0;
        }
    }

    internal sealed class SafeSspiContextHandle : SafeSspiHandle
    {
        internal SafeSspiContextHandle(Interop.SECURITY_HANDLE value)
            : base(value)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.SECURITY_HANDLE value = DangerousGetValue();
            uint status = Interop.DeleteSecurityContext(ref value);
            Clear();
            return status == 0;
        }
    }
}
