using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using FindGT.Core;

namespace FindGT.Eventing
{
    public static class Event4624Parser
    {
        private const string EventNamespace =
            "http://schemas.microsoft.com/win/2004/08/events/event";
        private const string SecurityProvider =
            "Microsoft-Windows-Security-Auditing";

        public static SessionCandidate Parse(string eventXml)
        {
            if (String.IsNullOrWhiteSpace(eventXml))
            {
                throw new EventParseException("Event XML is empty.");
            }

            XDocument document;
            try
            {
                document = XDocument.Parse(
                    eventXml,
                    LoadOptions.PreserveWhitespace);
            }
            catch (XmlException exception)
            {
                throw new EventParseException(
                    "Security Event 4624 XML is invalid.",
                    exception);
            }

            XNamespace ns = EventNamespace;
            XElement root = document.Root;
            XElement system = root == null ? null : root.Element(ns + "System");
            if (system == null)
            {
                throw new EventParseException("Event/System is missing.");
            }

            XElement provider = system.Element(ns + "Provider");
            string providerName = Attribute(provider, "Name");
            if (!String.Equals(
                providerName,
                SecurityProvider,
                StringComparison.Ordinal))
            {
                throw new EventParseException(
                    "Unexpected event provider: " + (providerName ?? "<missing>") + ".");
            }

            int eventId = ParseInt(ElementValue(system, ns + "EventID"), "EventID");
            if (eventId != 4624)
            {
                throw new EventParseException(
                    "Expected EventID 4624 but received " +
                    eventId.ToString(CultureInfo.InvariantCulture) + ".");
            }

            Dictionary<string, string> data = ReadNamedData(root, ns);
            string rawLogonId = Required(data, "TargetLogonId");
            LUID logonId;
            if (!LUID.TryParse(rawLogonId, out logonId))
            {
                throw new EventParseException(
                    "TargetLogonId is not a valid 64-bit LUID: " +
                    rawLogonId + ".");
            }

            uint logonType = ParseUInt(Required(data, "LogonType"), "LogonType");
            SessionTriggerContext trigger = new SessionTriggerContext
            {
                Source = TriggerSource.Event4624,
                EventRecordId = ParseNullableLong(
                    ElementValue(system, ns + "EventRecordID"),
                    "EventRecordID"),
                EventTimeUtc = ParseNullableDateTime(
                    Attribute(system.Element(ns + "TimeCreated"), "SystemTime"),
                    "TimeCreated"),
                TargetLogonId = logonId,
                TargetUserSid = Value(data, "TargetUserSid"),
                TargetUserName = Value(data, "TargetUserName"),
                TargetDomainName = Value(data, "TargetDomainName"),
                LogonType = logonType,
                AuthenticationPackage = Value(
                    data,
                    "AuthenticationPackageName"),
                LogonProcessName = Value(data, "LogonProcessName"),
                WorkstationName = Value(data, "WorkstationName"),
                IpAddress = Value(data, "IpAddress"),
                IpPort = Value(data, "IpPort"),
                ProcessId = Value(data, "ProcessId"),
                ProcessName = Value(data, "ProcessName"),
                LogonGuid = ParseNullableGuid(Value(data, "LogonGuid")),
                LinkedLogonId = ParseNullableLuid(Value(data, "LinkedLogonId"))
            };

            return new SessionCandidate
            {
                LogonId = logonId,
                Trigger = trigger,
                ObservedUtc = DateTime.UtcNow
            };
        }

        public static bool TryParse(
            string eventXml,
            out SessionCandidate candidate,
            out string error)
        {
            try
            {
                candidate = Parse(eventXml);
                error = null;
                return true;
            }
            catch (EventParseException exception)
            {
                candidate = null;
                error = exception.Message;
                return false;
            }
        }

        private static Dictionary<string, string> ReadNamedData(
            XElement root,
            XNamespace ns)
        {
            XElement eventData = root.Element(ns + "EventData");
            if (eventData == null)
            {
                throw new EventParseException("Event/EventData is missing.");
            }

            Dictionary<string, string> values =
                new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (XElement element in eventData.Elements(ns + "Data"))
            {
                string name = Attribute(element, "Name");
                if (!String.IsNullOrWhiteSpace(name) && !values.ContainsKey(name))
                {
                    values.Add(name, element.Value);
                }
            }

            return values;
        }

        private static string Required(
            IDictionary<string, string> values,
            string name)
        {
            string value = Value(values, name);
            if (String.IsNullOrWhiteSpace(value))
            {
                throw new EventParseException(name + " is missing.");
            }

            return value;
        }

        private static string Value(
            IDictionary<string, string> values,
            string name)
        {
            string value;
            return values.TryGetValue(name, out value) &&
                value != "-" ? value : null;
        }

        private static string ElementValue(XElement parent, XName name)
        {
            XElement element = parent.Element(name);
            return element == null ? null : element.Value;
        }

        private static string Attribute(XElement element, XName name)
        {
            XAttribute attribute = element == null ? null : element.Attribute(name);
            return attribute == null ? null : attribute.Value;
        }

        private static int ParseInt(string value, string field)
        {
            int result;
            if (!Int32.TryParse(
                value,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out result))
            {
                throw new EventParseException(field + " is not a valid integer.");
            }

            return result;
        }

        private static uint ParseUInt(string value, string field)
        {
            uint result;
            if (!UInt32.TryParse(
                value,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out result))
            {
                throw new EventParseException(field + " is not a valid unsigned integer.");
            }

            return result;
        }

        private static long? ParseNullableLong(string value, string field)
        {
            if (String.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            long result;
            if (!Int64.TryParse(
                value,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out result))
            {
                throw new EventParseException(field + " is not a valid integer.");
            }

            return result;
        }

        private static DateTime? ParseNullableDateTime(string value, string field)
        {
            if (String.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            DateTime result;
            if (!DateTime.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out result))
            {
                throw new EventParseException(field + " is not a valid timestamp.");
            }

            return DateTime.SpecifyKind(result, DateTimeKind.Utc);
        }

        private static Guid? ParseNullableGuid(string value)
        {
            if (String.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            Guid result;
            if (!Guid.TryParse(value, out result))
            {
                throw new EventParseException(
                    "LogonGuid is not a valid GUID.");
            }

            return result;
        }

        private static LUID? ParseNullableLuid(string value)
        {
            if (String.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            LUID result;
            if (!LUID.TryParse(value, out result))
            {
                throw new EventParseException(
                    "LinkedLogonId is not a valid 64-bit LUID.");
            }

            return result;
        }
    }
}
