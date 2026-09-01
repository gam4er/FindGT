using System;
using System.Globalization;

namespace FindGT
{
    /// <summary>Preserves the native operation, status and LUID for diagnostics.</summary>
    internal sealed class NativeCallException : Exception
    {
        internal NativeCallException(
            string operation,
            uint statusCode,
            LUID? logonId,
            int? win32ErrorCode,
            string detail)
            : base(BuildMessage(operation, statusCode, logonId, win32ErrorCode, detail))
        {
            Operation = operation;
            StatusCode = statusCode;
            LogonId = logonId;
            Win32ErrorCode = win32ErrorCode;
        }

        internal string Operation { get; private set; }
        internal uint StatusCode { get; private set; }
        internal LUID? LogonId { get; private set; }
        internal int? Win32ErrorCode { get; private set; }

        internal static NativeCallException FromNtStatus(
            string operation,
            uint statusCode,
            LUID? logonId,
            string detail)
        {
            return new NativeCallException(
                operation,
                statusCode,
                logonId,
                checked((int)Interop.LsaNtStatusToWinError(statusCode)),
                detail);
        }

        internal static NativeCallException FromSecurityStatus(
            string operation,
            uint statusCode,
            LUID? logonId,
            string detail)
        {
            return new NativeCallException(
                operation,
                statusCode,
                logonId,
                unchecked((int)statusCode),
                detail);
        }

        private static string BuildMessage(
            string operation,
            uint statusCode,
            LUID? logonId,
            int? win32ErrorCode,
            string detail)
        {
            string message = String.Format(
                CultureInfo.InvariantCulture,
                "{0} failed with status 0x{1:X8}",
                operation,
                statusCode);

            if (win32ErrorCode.HasValue)
            {
                message += String.Format(
                    CultureInfo.InvariantCulture,
                    " (Win32 {0})",
                    win32ErrorCode.Value);
            }

            if (logonId.HasValue)
            {
                message += " for LUID " + logonId.Value;
            }

            if (!String.IsNullOrWhiteSpace(detail))
            {
                message += ": " + detail;
            }

            return message;
        }
    }
}
