using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace FindGT
{
    public static class Find
    {
        public struct FoundSession
        {
            public LUID LogonId;
            public string UserName;
            public string AccountName;
            public string CredentialUserName;
            public string LogonDomain;
            public string DnsDomainName;
            public string Upn;
            public string Sid;
            public Interop.SECURITY_LOGON_TYPE LogonType;
            public string AuthenticationPackage;
            public uint Session;
            public DateTime? LogonTimeUtc;
            public string LogonServer;
            public uint UserFlags;
        }

        public static Dictionary<LUID, FoundSession> LogonSessions(
            bool debug,
            Action<string> errorLog)
        {
            if (errorLog == null)
            {
                errorLog = delegate(string message) { Console.Error.WriteLine(message); };
            }

            ulong count;
            IntPtr rawList;
            uint status = Interop.LsaEnumerateLogonSessions(out count, out rawList);
            if (status != 0)
            {
                throw NativeCallException.FromNtStatus(
                    "LsaEnumerateLogonSessions",
                    status,
                    null,
                    null);
            }

            if (count > Int32.MaxValue)
            {
                if (rawList != IntPtr.Zero)
                {
                    Interop.LsaFreeReturnBuffer(rawList);
                }

                throw new InvalidOperationException(
                    "LsaEnumerateLogonSessions returned an unsupported session count.");
            }

            Dictionary<LUID, FoundSession> sessions =
                new Dictionary<LUID, FoundSession>();

            using (SafeLsaReturnBuffer list = new SafeLsaReturnBuffer(rawList))
            {
                if (count != 0 && list.IsInvalid)
                {
                    throw new InvalidOperationException(
                        "LsaEnumerateLogonSessions returned a null session list.");
                }

                int luidSize = Marshal.SizeOf(typeof(LUID));
                for (int index = 0; index < (int)count; index++)
                {
                    long offset = checked((long)index * luidSize);
                    IntPtr luidPointer = new IntPtr(
                        checked(list.DangerousGetHandle().ToInt64() + offset));
                    LUID enumeratedLogonId = (LUID)Marshal.PtrToStructure(
                        luidPointer,
                        typeof(LUID));

                    IntPtr rawSessionData;
                    status = Interop.LsaGetLogonSessionData(
                        ref enumeratedLogonId,
                        out rawSessionData);

                    if (status != 0)
                    {
                        errorLog(FormatNativeError(
                            "LsaGetLogonSessionData",
                            status,
                            enumeratedLogonId));
                        continue;
                    }

                    using (SafeLsaReturnBuffer sessionData =
                        new SafeLsaReturnBuffer(rawSessionData))
                    {
                        if (sessionData.IsInvalid)
                        {
                            errorLog(
                                "LsaGetLogonSessionData returned a null buffer for LUID " +
                                enumeratedLogonId + ".");
                            continue;
                        }

                        try
                        {
                            FoundSession session = ReadSession(
                                sessionData.DangerousGetHandle(),
                                enumeratedLogonId,
                                debug,
                                errorLog);

                            if ((TokenInspector.IsDomainSid(session.Sid) ||
                                 session.LogonType == Interop.SECURITY_LOGON_TYPE.NewCredentials) &&
                                !String.IsNullOrEmpty(session.AuthenticationPackage))
                            {
                                sessions[session.LogonId] = session;
                            }
                        }
                        catch (ArgumentException exception)
                        {
                            errorLog(
                                "Invalid LSA session data for LUID " +
                                enumeratedLogonId + ": " + exception.Message);
                        }
                        catch (OverflowException exception)
                        {
                            errorLog(
                                "Out-of-range LSA session data for LUID " +
                                enumeratedLogonId + ": " + exception.Message);
                        }
                    }
                }
            }

            return sessions;
        }

        public static Dictionary<LUID, FoundSession> LogonSessions(bool debug)
        {
            return LogonSessions(debug, null);
        }

        internal static FoundSession? GetLogonSession(
            LUID logonId,
            bool debug,
            Action<string> errorLog)
        {
            IntPtr rawSessionData;
            uint status = Interop.LsaGetLogonSessionData(
                ref logonId,
                out rawSessionData);

            if (status != 0)
            {
                int win32Error = checked((int)Interop.LsaNtStatusToWinError(status));
                if (win32Error == 1312)
                {
                    return null;
                }

                throw NativeCallException.FromNtStatus(
                    "LsaGetLogonSessionData",
                    status,
                    logonId,
                    null);
            }

            using (SafeLsaReturnBuffer sessionData =
                new SafeLsaReturnBuffer(rawSessionData))
            {
                if (sessionData.IsInvalid)
                {
                    return null;
                }

                return ReadSession(
                    sessionData.DangerousGetHandle(),
                    logonId,
                    debug,
                    errorLog ?? delegate { });
            }
        }

        private static FoundSession ReadSession(
            IntPtr sessionData,
            LUID enumeratedLogonId,
            bool debug,
            Action<string> errorLog)
        {
            Interop.SECURITY_LOGON_SESSION_DATA data =
                (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(
                    sessionData,
                    typeof(Interop.SECURITY_LOGON_SESSION_DATA));

            if (data.LoginID != enumeratedLogonId)
            {
                errorLog(
                    "LSA returned LUID " + data.LoginID +
                    " for enumeration candidate " + enumeratedLogonId + ".");
            }

            if (data.PSiD == IntPtr.Zero)
            {
                throw new ArgumentException("The session does not contain a user SID.");
            }

            SecurityIdentifier sid = new SecurityIdentifier(data.PSiD);
            string accountName = ReadLsaString(data.Username);
            string domain = ReadLsaString(data.LoginDomain);
            Interop.SECURITY_LOGON_TYPE logonType =
                (Interop.SECURITY_LOGON_TYPE)data.LogonType;

            string credentialUserName = String.Empty;
            if (logonType == Interop.SECURITY_LOGON_TYPE.NewCredentials)
            {
                credentialUserName = Creds.GetCredentialUserName(data.LoginID, debug);
            }

            return new FoundSession
            {
                LogonId = data.LoginID,
                UserName = String.IsNullOrEmpty(domain)
                    ? accountName
                    : domain + "\\" + accountName,
                AccountName = accountName,
                CredentialUserName = credentialUserName,
                LogonDomain = domain,
                DnsDomainName = ReadLsaString(data.DnsDomainName),
                Upn = ReadLsaString(data.Upn),
                Sid = sid.Value,
                LogonType = logonType,
                AuthenticationPackage = ReadLsaString(data.AuthenticationPackage),
                Session = data.Session,
                LogonTimeUtc = ReadFileTime(data.LoginTime),
                LogonServer = ReadLsaString(data.LogonServer),
                UserFlags = data.UserFlags
            };
        }

        private static string ReadLsaString(Interop.LSA_STRING value)
        {
            if (value.Buffer == IntPtr.Zero || value.Length == 0)
            {
                return String.Empty;
            }

            if ((value.Length & 1) != 0)
            {
                throw new ArgumentException(
                    "An LSA Unicode string has an odd byte length.");
            }

            string result = Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
            return result == null ? String.Empty : result.TrimEnd('\0');
        }

        private static DateTime? ReadFileTime(long value)
        {
            if (value <= 0)
            {
                return null;
            }

            return DateTime.FromFileTimeUtc(value);
        }

        private static string FormatNativeError(
            string operation,
            uint status,
            LUID logonId)
        {
            return String.Format(
                CultureInfo.InvariantCulture,
                "{0} failed with NTSTATUS 0x{1:X8} (Win32 {2}) for LUID {3}.",
                operation,
                status,
                Interop.LsaNtStatusToWinError(status),
                logonId);
        }
    }
}
