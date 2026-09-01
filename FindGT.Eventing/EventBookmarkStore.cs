using System;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace FindGT.Eventing
{
    public sealed class EventBookmarkStore
    {
        private readonly string _path;

        public EventBookmarkStore(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("A bookmark path is required.", "path");
            }

            _path = System.IO.Path.GetFullPath(
                Environment.ExpandEnvironmentVariables(path));
        }

        public string Path
        {
            get { return _path; }
        }

        public bool TryLoad(out EventBookmark bookmark, out string error)
        {
            bookmark = null;
            error = null;
            string backupPath = _path + ".bak";
            if (!File.Exists(_path) && !File.Exists(backupPath))
            {
                return true;
            }

            string primaryError;
            if (TryLoadFile(_path, out bookmark, out primaryError))
            {
                return true;
            }

            string backupError;
            if (TryLoadFile(backupPath, out bookmark, out backupError))
            {
                error = "Primary bookmark is invalid; using last-known-good backup: " +
                    primaryError;
                return true;
            }

            error = "Primary bookmark: " + primaryError +
                " | Backup bookmark: " + backupError;
            return false;
        }

        private static bool TryLoadFile(
            string path,
            out EventBookmark bookmark,
            out string error)
        {
            bookmark = null;
            error = null;
            if (!File.Exists(path))
            {
                error = "File not found.";
                return false;
            }

            try
            {
                string xml = File.ReadAllText(path, Encoding.UTF8);
                if (String.IsNullOrWhiteSpace(xml))
                {
                    error = "The bookmark file is empty.";
                    return false;
                }

                XDocument.Parse(xml, LoadOptions.None);
                bookmark = EventBookmarkCompatibility.FromXml(xml);
                return true;
            }
            catch (IOException exception)
            {
                error = exception.Message;
            }
            catch (UnauthorizedAccessException exception)
            {
                error = exception.Message;
            }
            catch (ArgumentException exception)
            {
                error = exception.Message;
            }
            catch (EventLogException exception)
            {
                error = exception.Message;
            }
            catch (XmlException exception)
            {
                error = exception.Message;
            }
            catch (EventParseException exception)
            {
                error = exception.Message;
            }
            catch (PlatformNotSupportedException exception)
            {
                error = exception.Message;
            }

            return false;
        }

        public void Save(EventBookmark bookmark)
        {
            if (bookmark == null)
            {
                throw new ArgumentNullException("bookmark");
            }

            string directory = System.IO.Path.GetDirectoryName(_path);
            if (String.IsNullOrWhiteSpace(directory))
            {
                throw new InvalidOperationException(
                    "The bookmark path does not have a parent directory.");
            }

            Directory.CreateDirectory(directory);
            string temporaryPath = _path + "." +
                Guid.NewGuid().ToString("N") + ".tmp";

            try
            {
                using (FileStream stream = new FileStream(
                    temporaryPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    4096,
                    FileOptions.WriteThrough))
                using (StreamWriter writer = new StreamWriter(
                    stream,
                    new UTF8Encoding(false)))
                {
                    writer.Write(EventBookmarkCompatibility.ToXml(bookmark));
                    writer.Flush();
                    stream.Flush(true);
                }

                if (File.Exists(_path))
                {
                    File.Replace(
                        temporaryPath,
                        _path,
                        _path + ".bak",
                        true);
                }
                else
                {
                    File.Move(temporaryPath, _path);
                }
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }
        }
    }
}
