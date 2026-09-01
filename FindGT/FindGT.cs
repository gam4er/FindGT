using System;
using System.IO;
using System.Security;
using Spectre.Console.Cli;

namespace FindGT
{
    public static class FindGT
    {
        static int Main(string[] args)
        {
            try
            {
                Console.OutputEncoding = System.Text.Encoding.UTF8;
            }
            catch (IOException exception)
            {
                Console.Error.WriteLine("Unable to set UTF-8 console output: " + exception.Message);
            }
            catch (SecurityException exception)
            {
                Console.Error.WriteLine("Unable to set UTF-8 console output: " + exception.Message);
            }

            var app = new Spectre.Console.Cli.CommandApp<Cli.ScanCommand>();
            app.Configure(config =>
            {
                config.SetApplicationName("FindGT");
                config.AddCommand<Cli.TestS4uCommand>("test-s4u");
                config.AddCommand<Cli.TestSecureChannelCommand>("test-securechannel");
                config.AddCommand<Cli.TestSecureChannelRawCommand>("test-securechannel-raw");
                config.AddCommand<Cli.TestCryptoCommand>("test-crypto");
            });
            return app.Run(args);
        }
    }
}
