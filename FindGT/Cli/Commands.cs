using System.ComponentModel;
using Spectre.Console.Cli;
using FindGT.Reporting;

namespace FindGT.Cli
{
    public sealed class ScanSettings : CommandSettings
    {
        [CommandOption("-v|--verbose")]
        [Description("Показать все группы каждой сессии, а не только расхождения")]
        public bool Verbose { get; set; }

        [CommandOption("--html")]
        [Description("Сохранить отчёт как HTML-файл в текущую папку")]
        public bool Html { get; set; }
    }

    /// <summary>Default command: enumerate Kerberos sessions and diff token vs authoritative membership.</summary>
    public sealed class ScanCommand : Command<ScanSettings>
    {
        public override int Execute(CommandContext context, ScanSettings settings)
        {
            if (settings.Html)
                Ui.BeginRecord();
            if (!AppRunner.EnsureSystem())
                return 2;
            return AppRunner.RunReport(settings.Verbose, settings.Html);
        }
    }

    public sealed class TestS4uSettings : CommandSettings
    {
        [CommandArgument(0, "<upn>")]
        [Description("UPN (user@realm) или DOMAIN\\user целевого пользователя")]
        public string Upn { get; set; }

        [CommandArgument(1, "[realm]")]
        [Description("Realm, если он не указан в UPN")]
        public string Realm { get; set; }
    }

    public sealed class TestS4uCommand : Command<TestS4uSettings>
    {
        public override int Execute(CommandContext context, TestS4uSettings settings)
        {
            if (!AppRunner.EnsureSystem())
                return 2;
            S4U.Test(settings.Upn, settings.Realm);
            return 0;
        }
    }

    public sealed class TestSecureChannelSettings : CommandSettings
    {
        [CommandArgument(0, "<nthash-file>")]
        [Description("Файл с NT-хэшем (hex) машинной учётной записи")]
        public string HashFile { get; set; }

        [CommandArgument(1, "[dc]")]
        [Description("Имя контроллера домена (\\\\dc.fqdn); по умолчанию — автопоиск")]
        public string Dc { get; set; }
    }

    public sealed class TestSecureChannelCommand : Command<TestSecureChannelSettings>
    {
        public override int Execute(CommandContext context, TestSecureChannelSettings settings)
        {
            Nrpc.TestSecureChannel(settings.HashFile, settings.Dc);
            return 0;
        }
    }

    public sealed class TestSecureChannelRawSettings : CommandSettings
    {
        [CommandArgument(0, "<raw-secret-file>")]
        [Description("Файл с сырым секретом машинной учётной записи")]
        public string RawFile { get; set; }

        [CommandArgument(1, "[dc]")]
        [Description("Имя контроллера домена; по умолчанию — автопоиск")]
        public string Dc { get; set; }
    }

    public sealed class TestSecureChannelRawCommand : Command<TestSecureChannelRawSettings>
    {
        public override int Execute(CommandContext context, TestSecureChannelRawSettings settings)
        {
            Nrpc.TestSecureChannelRaw(settings.RawFile, settings.Dc);
            return 0;
        }
    }

    public sealed class EmptySettings : CommandSettings
    {
    }

    public sealed class TestCryptoCommand : Command<EmptySettings>
    {
        public override int Execute(CommandContext context, EmptySettings settings)
        {
            Nrpc.TestCrypto();
            return 0;
        }
    }
}
