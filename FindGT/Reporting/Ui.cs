using Spectre.Console;

namespace FindGT.Reporting
{
    /// <summary>Operational (non-report) console output, routed through Spectre so it is styled
    /// and captured into the HTML recording like the rest of the output.</summary>
    public static class Ui
    {
        public static void BeginRecord()
        {
            AnsiConsole.Record();
        }

        public static void Info(string message)
        {
            AnsiConsole.MarkupLine("[grey]" + Markup.Escape(message) + "[/]");
        }

        public static void Success(string message)
        {
            AnsiConsole.MarkupLine("[green]" + Markup.Escape(message) + "[/]");
        }

        public static void Warn(string message)
        {
            AnsiConsole.MarkupLine("[yellow]" + Markup.Escape(message) + "[/]");
        }

        public static void Error(string message)
        {
            AnsiConsole.MarkupLine("[red]" + Markup.Escape(message) + "[/]");
        }
    }
}
