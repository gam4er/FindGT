using System;

namespace FindGT.Eventing
{
    public sealed class EventParseException : Exception
    {
        public EventParseException(string message)
            : base(message)
        {
        }

        public EventParseException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
