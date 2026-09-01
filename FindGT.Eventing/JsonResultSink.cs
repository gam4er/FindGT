using System;
using System.IO;
using System.Security;
using System.Text;
using FindGT.Core;

namespace FindGT.Eventing
{
    internal sealed class JsonResultSink : IDisposable
    {
        private const long MaximumFileBytes = 50L * 1024L * 1024L;
        private readonly object _sync = new object();
        private readonly string _directory;

        internal JsonResultSink(string directory)
        {
            if (String.IsNullOrWhiteSpace(directory))
            {
                throw new ArgumentException(
                    "A JSON output directory is required.",
                    "directory");
            }

            _directory = Path.GetFullPath(
                Environment.ExpandEnvironmentVariables(directory));
        }

        internal bool WriteAnalysis(
            SessionAnalysisResult result,
            out string error)
        {
            return Append(
                AnalysisPayloadSerializer.SerializeAnalysisForJson(result),
                out error);
        }

        internal bool WriteServiceEvent(
            ServiceEventRecord record,
            out string error)
        {
            return Append(
                AnalysisPayloadSerializer.SerializeServiceEvent(record),
                out error);
        }

        public void Dispose()
        {
        }

        private bool Append(string payload, out string error)
        {
            try
            {
                lock (_sync)
                {
                    Directory.CreateDirectory(_directory);
                    string path = CurrentPath();
                    byte[] line = new UTF8Encoding(false).GetBytes(
                        payload + Environment.NewLine);
                    using (FileStream stream = new FileStream(
                        path,
                        FileMode.Append,
                        FileAccess.Write,
                        FileShare.Read,
                        4096,
                        FileOptions.WriteThrough))
                    {
                        stream.Write(line, 0, line.Length);
                        stream.Flush(true);
                    }
                }

                error = null;
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
            catch (SecurityException exception)
            {
                error = exception.Message;
            }
            catch (ArgumentException exception)
            {
                error = exception.Message;
            }
            catch (NotSupportedException exception)
            {
                error = exception.Message;
            }

            return false;
        }

        private string CurrentPath()
        {
            string baseName = "findgt-" +
                DateTime.UtcNow.ToString("yyyy-MM-dd");
            string path = Path.Combine(_directory, baseName + ".jsonl");
            if (!File.Exists(path) ||
                new FileInfo(path).Length < MaximumFileBytes)
            {
                return path;
            }

            for (int index = 1; index < Int32.MaxValue; index++)
            {
                path = Path.Combine(
                    _directory,
                    baseName + "." + index + ".jsonl");
                if (!File.Exists(path) ||
                    new FileInfo(path).Length < MaximumFileBytes)
                {
                    return path;
                }
            }

            throw new IOException("No JSON rotation filename is available.");
        }
    }
}
