using System;
using System.Linq;
using System.ServiceProcess;
using System.Threading;
using FindGT.Service.Runtime;

namespace FindGT.Service
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            bool console = args.Any(argument =>
                String.Equals(
                    argument,
                    "--console",
                    StringComparison.OrdinalIgnoreCase));
            if (args.Any(argument =>
                String.Equals(
                    argument,
                    "--help",
                    StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine(
                    "Usage: FindGT.Service.exe [--console] [--config <path>]");
                return 0;
            }

            string configurationPath = ReadOption(args, "--config");
            if (!console)
            {
                ServiceBase.Run(new FindGtWindowsService(configurationPath));
                return 0;
            }

            using (FindGtServiceRuntime runtime = ServiceRuntimeFactory.Create(
                configurationPath,
                true))
            using (ManualResetEvent stop = new ManualResetEvent(false))
            {
                ConsoleCancelEventHandler cancel = delegate(
                    object sender,
                    ConsoleCancelEventArgs eventArgs)
                {
                    eventArgs.Cancel = true;
                    stop.Set();
                };

                Console.CancelKeyPress += cancel;
                try
                {
                    runtime.Start();
                    Console.WriteLine(
                        "FindGT service runtime is active. Press Ctrl+C to stop.");
                    stop.WaitOne();
                    runtime.Stop(TimeSpan.FromSeconds(25));
                }
                finally
                {
                    Console.CancelKeyPress -= cancel;
                }
            }

            return 0;
        }

        private static string ReadOption(string[] args, string option)
        {
            for (int index = 0; index < args.Length; index++)
            {
                if (!String.Equals(
                    args[index],
                    option,
                    StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (index == args.Length - 1 ||
                    String.IsNullOrWhiteSpace(args[index + 1]))
                {
                    throw new ArgumentException(
                        option + " requires a value.");
                }

                return args[index + 1];
            }

            return null;
        }
    }
}
