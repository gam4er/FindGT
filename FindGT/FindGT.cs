using System;
using Spectre.Console.Cli;

namespace FindGT
{
    public static class FindGT
    {
        static int Main(string[] args)
        {
            try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { }

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
