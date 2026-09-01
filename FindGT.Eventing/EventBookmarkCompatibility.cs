using System;
using System.Diagnostics.Eventing.Reader;
using System.Reflection;

namespace FindGT.Eventing
{
    internal static class EventBookmarkCompatibility
    {
        private static readonly ConstructorInfo BookmarkConstructor =
            typeof(EventBookmark).GetConstructor(
                BindingFlags.Instance | BindingFlags.NonPublic,
                null,
                new[] { typeof(string) },
                null);

        private static readonly PropertyInfo BookmarkTextProperty =
            typeof(EventBookmark).GetProperty(
                "BookmarkText",
                BindingFlags.Instance | BindingFlags.NonPublic);

        internal static EventBookmark FromXml(string xml)
        {
            EnsureSupported();
            try
            {
                return (EventBookmark)BookmarkConstructor.Invoke(
                    new object[] { xml });
            }
            catch (TargetInvocationException exception)
            {
                throw new EventParseException(
                    "The persisted EventBookmark XML is invalid.",
                    exception.InnerException ?? exception);
            }
        }

        internal static string ToXml(EventBookmark bookmark)
        {
            if (bookmark == null)
            {
                throw new ArgumentNullException("bookmark");
            }

            EnsureSupported();
            string value = (string)BookmarkTextProperty.GetValue(bookmark, null);
            if (String.IsNullOrWhiteSpace(value))
            {
                throw new EventParseException(
                    "The EventBookmark does not contain XML.");
            }

            return value;
        }

        private static void EnsureSupported()
        {
            if (BookmarkConstructor == null || BookmarkTextProperty == null)
            {
                throw new PlatformNotSupportedException(
                    "This .NET Framework runtime does not expose the EventBookmark XML compatibility surface.");
            }
        }
    }
}
