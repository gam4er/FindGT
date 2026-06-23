using System;
using System.Collections.Generic;
using System.IO;
using Spectre.Console;
using FindGT.Membership;

namespace FindGT.Reporting
{
    /// <summary>
    /// Renders per-session membership comparison results with Spectre.Console.
    /// Default = only discrepancies; verbose = every group. Optionally records the whole
    /// run and exports it as an HTML file into the current directory.
    /// </summary>
    public class SpectreReporter
    {
        private readonly bool _verbose;
        private readonly bool _html;
        private int _sessionCount;
        private int _suspiciousSessions;

        public SpectreReporter(bool verbose, bool html)
        {
            _verbose = verbose;
            _html = html;
        }

        public void Header()
        {
            AnsiConsole.Write(new Rule("[bold red]FindGT[/] [grey]— проверка членства против эталона (Golden Ticket)[/]")
                .LeftJustified().RuleStyle("grey"));
            AnsiConsole.WriteLine();
        }

        public void RenderSession(SessionReport r)
        {
            _sessionCount++;
            if (r.HasSuspicious) _suspiciousSessions++;

            string who = r.UserName ?? r.UserSid ?? "?";
            string title = "Сессия " + (r.Luid ?? "?") + "  |  " + who + "  |  " + (r.AuthPackage ?? "?");
            AnsiConsole.Write(new Rule("[bold]" + Markup.Escape(title) + "[/]")
                .LeftJustified().RuleStyle(r.HasSuspicious ? "red" : "green"));

            if (r.ReferenceOk)
            {
                AnsiConsole.MarkupLine("  Эталон: [green]" + Markup.Escape(r.ReferenceSource ?? "") + "[/]" +
                    "   групп: токен=[bold]" + r.TokenDomainGroupCount + "[/], эталон=[bold]" + r.ReferenceDomainGroupCount + "[/]");
            }
            else
            {
                AnsiConsole.MarkupLine("  Эталон: [red]ОШИБКА (" + Markup.Escape(r.ReferenceSource ?? "") + ")[/] — " +
                    Markup.Escape(r.ReferenceError ?? ""));
            }

            var shown = new List<DiffRow>();
            foreach (var row in r.Rows)
                if (_verbose || row.Kind != DiffKind.Match)
                    shown.Add(row);

            if (shown.Count == 0)
            {
                AnsiConsole.MarkupLine("  [green]✓ Расхождений нет[/]");
                AnsiConsole.WriteLine();
                return;
            }

            var table = new Table().Border(TableBorder.Rounded).Expand();
            table.AddColumn("[grey]SID группы[/]");
            table.AddColumn("[grey]Имя[/]");
            table.AddColumn("[grey]Комментарий[/]");

            foreach (var row in shown)
            {
                string style;
                string comment;
                switch (row.Kind)
                {
                    case DiffKind.InSessionNotInReference:
                        if (row.IsUserSid)
                        {
                            style = "bold red";
                            comment = "⚠ SID ПОЛЬЗОВАТЕЛЯ, а не группы — есть в сессии, нет в эталоне";
                        }
                        else
                        {
                            style = "red";
                            comment = "есть в сессии, но НЕ должно быть (нет в эталоне)";
                        }
                        break;
                    case DiffKind.InReferenceNotInSession:
                        style = "yellow";
                        comment = "должна быть (есть в эталоне), но НЕТ в сессии";
                        break;
                    default:
                        style = "grey";
                        comment = "OK — есть и в сессии, и в эталоне";
                        break;
                }

                table.AddRow(
                    "[" + style + "]" + Markup.Escape(row.Sid ?? "") + "[/]",
                    "[" + style + "]" + Markup.Escape(row.Name ?? "(не разрешено)") + "[/]",
                    "[" + style + "]" + Markup.Escape(comment) + "[/]");
            }

            AnsiConsole.Write(table);
            AnsiConsole.WriteLine();
        }

        public void Finish()
        {
            AnsiConsole.Write(new Rule("[bold]Итог[/]").LeftJustified().RuleStyle("grey"));
            string color = _suspiciousSessions > 0 ? "red" : "green";
            AnsiConsole.MarkupLine("Сессий проверено: [bold]" + _sessionCount + "[/]   " +
                "с расхождениями: [bold " + color + "]" + _suspiciousSessions + "[/]");

            if (_html)
            {
                try
                {
                    string body = AnsiConsole.ExportHtml();
                    string doc = "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n" +
                                 "<title>FindGT — отчёт о членстве</title>\n" +
                                 "<style>body{background:#0c0c0c;color:#cccccc;margin:1em;}</style>\n" +
                                 "</head>\n<body>\n" + body + "\n</body>\n</html>\n";
                    string name = "FindGT-report-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".html";
                    string path = Path.Combine(Directory.GetCurrentDirectory(), name);
                    File.WriteAllText(path, doc, new System.Text.UTF8Encoding(false));
                    AnsiConsole.MarkupLine("HTML-отчёт сохранён: [blue]" + Markup.Escape(path) + "[/]");
                }
                catch (Exception ex)
                {
                    AnsiConsole.MarkupLine("[red]Не удалось сохранить HTML:[/] " + Markup.Escape(ex.Message));
                }
            }
        }
    }
}
