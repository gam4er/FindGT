using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace FindGT
{
    /// <summary>Converts an existing logon-session credential into an inspectable token.</summary>
    internal static class Creds
    {
        private const int MaxTokenSize = 12288;
        private const uint SecEOk = 0;
        private const uint SecIContinueNeeded = 0x00090312;
        private const uint SecENoCredentials = 0x8009030E;
        private const int SecPkgCredBoth = 3;
        private const int IscReqConnection = 0x00000800;
        private const int SecurityNativeDrep = 0x10;
        private const uint SecPkgCredAttrNames = 1;

        internal static string GetCredentialUserName(LUID luid, bool debug)
        {
            try
            {
                using (SafeSspiCredentialHandle credential = AcquireCredentialHandle(luid, null))
                {
                    Interop.SECURITY_HANDLE nativeCredential = credential.DangerousGetValue();
                    IntPtr credentialName = IntPtr.Zero;
                    uint status = Interop.QueryCredentialsAttributes(
                        ref nativeCredential,
                        SecPkgCredAttrNames,
                        out credentialName);

                    if (status != SecEOk)
                    {
                        throw NativeCallException.FromSecurityStatus(
                            "QueryCredentialsAttributes",
                            status,
                            luid,
                            null);
                    }

                    try
                    {
                        string value = Marshal.PtrToStringUni(credentialName);
                        return value == null ? String.Empty : value.Trim();
                    }
                    finally
                    {
                        if (credentialName != IntPtr.Zero)
                        {
                            Interop.FreeContextBuffer(credentialName);
                        }
                    }
                }
            }
            catch (NativeCallException exception)
            {
                if (debug)
                {
                    Console.WriteLine("DEBUG " + exception.Message);
                }

                return String.Empty;
            }
        }

        internal static SafeKernelHandle NegotiateToken(
            LUID luid,
            ConcurrentDictionary<string, int> metadata,
            bool debug)
        {
            SecBufferDesc clientToken = SecBufferDesc.Empty;
            SecBufferDesc clientToken2 = SecBufferDesc.Empty;
            SecBufferDesc serverToken = SecBufferDesc.Empty;
            SafeSspiContextHandle clientContext = null;
            SafeSspiContextHandle serverContext = null;

            try
            {
                clientToken = new SecBufferDesc(MaxTokenSize);
                clientToken2 = new SecBufferDesc(MaxTokenSize);
                serverToken = new SecBufferDesc(MaxTokenSize);

                using (SafeSspiCredentialHandle credential = AcquireCredentialHandle(luid, metadata))
                {
                    Interop.SECURITY_HANDLE nativeCredential = credential.DangerousGetValue();
                    Interop.SECURITY_INTEGER lifetime;
                    uint contextAttributes;

                    Interop.SECURITY_HANDLE nativeClientContext;
                    uint status = Interop.InitializeSecurityContext(
                        ref nativeCredential,
                        IntPtr.Zero,
                        String.Empty,
                        IscReqConnection,
                        0,
                        SecurityNativeDrep,
                        IntPtr.Zero,
                        0,
                        out nativeClientContext,
                        ref clientToken,
                        out contextAttributes,
                        out lifetime);

                    clientContext = new SafeSspiContextHandle(nativeClientContext);
                    EnsureStatus(
                        "InitializeSecurityContext(initial)",
                        status,
                        SecIContinueNeeded,
                        luid);

                    Interop.SECURITY_HANDLE nativeServerContext;
                    status = Interop.AcceptSecurityContext(
                        ref nativeCredential,
                        IntPtr.Zero,
                        ref clientToken,
                        (uint)IscReqConnection,
                        (uint)SecurityNativeDrep,
                        out nativeServerContext,
                        ref serverToken,
                        out contextAttributes,
                        out lifetime);

                    serverContext = new SafeSspiContextHandle(nativeServerContext);
                    EnsureStatus(
                        "AcceptSecurityContext(initial)",
                        status,
                        SecIContinueNeeded,
                        luid);

                    Interop.SECURITY_HANDLE currentClientContext = clientContext.DangerousGetValue();
                    status = Interop.InitializeSecurityContext(
                        ref nativeCredential,
                        ref currentClientContext,
                        String.Empty,
                        IscReqConnection,
                        0,
                        SecurityNativeDrep,
                        ref serverToken,
                        0,
                        out currentClientContext,
                        ref clientToken2,
                        out contextAttributes,
                        out lifetime);

                    if (!currentClientContext.IsZero)
                    {
                        clientContext.SetValue(currentClientContext);
                    }

                    if (status != SecIContinueNeeded && status != SecEOk)
                    {
                        throw NativeCallException.FromSecurityStatus(
                            "InitializeSecurityContext(final)",
                            status,
                            luid,
                            null);
                    }

                    Interop.SECURITY_HANDLE currentServerContext = serverContext.DangerousGetValue();
                    status = Interop.AcceptSecurityContext(
                        ref nativeCredential,
                        ref currentServerContext,
                        ref clientToken2,
                        (uint)IscReqConnection,
                        (uint)SecurityNativeDrep,
                        out currentServerContext,
                        ref serverToken,
                        out contextAttributes,
                        out lifetime);

                    if (!currentServerContext.IsZero)
                    {
                        serverContext.SetValue(currentServerContext);
                    }

                    EnsureStatus(
                        "AcceptSecurityContext(final)",
                        status,
                        SecEOk,
                        luid);

                    currentServerContext = serverContext.DangerousGetValue();
                    IntPtr rawToken;
                    status = Interop.QuerySecurityContextToken(ref currentServerContext, out rawToken);
                    if (status != SecEOk)
                    {
                        throw NativeCallException.FromSecurityStatus(
                            "QuerySecurityContextToken",
                            status,
                            luid,
                            null);
                    }

                    if (debug)
                    {
                        Console.WriteLine("DEBUG Successfully negotiated LUID " + luid + " to a token.");
                    }

                    return new SafeKernelHandle(rawToken);
                }
            }
            finally
            {
                if (clientContext != null)
                {
                    clientContext.Dispose();
                }

                if (serverContext != null)
                {
                    serverContext.Dispose();
                }

                clientToken.Dispose();
                clientToken2.Dispose();
                serverToken.Dispose();
            }
        }

        private static SafeSspiCredentialHandle AcquireCredentialHandle(
            LUID luid,
            ConcurrentDictionary<string, int> metadata)
        {
            using (SafeHGlobalBuffer luidBuffer = SafeHGlobalBuffer.Allocate(Marshal.SizeOf(typeof(LUID))))
            {
                Marshal.StructureToPtr(luid, luidBuffer.DangerousGetHandle(), false);

                Interop.SECURITY_HANDLE nativeCredential = Interop.SECURITY_HANDLE.Empty;
                Interop.FILETIME lifetime = new Interop.FILETIME();
                uint status = Interop.AcquireCredentialsHandle(
                    String.Empty,
                    "Negotiate",
                    SecPkgCredBoth,
                    luidBuffer.DangerousGetHandle(),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref nativeCredential,
                    ref lifetime);

                SafeSspiCredentialHandle credential = new SafeSspiCredentialHandle(nativeCredential);
                if (status == SecEOk)
                {
                    return credential;
                }

                credential.Dispose();
                Increment(metadata, "AcquireCredentialsHandleError");
                string detail = status == SecENoCredentials
                    ? "SEC_E_NO_CREDENTIALS"
                    : null;

                throw NativeCallException.FromSecurityStatus(
                    "AcquireCredentialsHandle",
                    status,
                    luid,
                    detail);
            }
        }

        private static void EnsureStatus(
            string operation,
            uint actual,
            uint expected,
            LUID luid)
        {
            if (actual != expected)
            {
                throw NativeCallException.FromSecurityStatus(
                    operation,
                    actual,
                    luid,
                    "expected 0x" + expected.ToString("X8"));
            }
        }

        private static void Increment(
            ConcurrentDictionary<string, int> metadata,
            string key)
        {
            if (metadata != null)
            {
                metadata.AddOrUpdate(key, 1, delegate(string _, int current) { return current + 1; });
            }
        }
    }
}
