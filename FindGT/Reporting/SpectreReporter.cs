using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
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
        private int _unknownSessions;
        private int _notEvaluatedSessions;

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
            if (r.IsUnknown) _unknownSessions++;
            if (r.IsNotEvaluated) _notEvaluatedSessions++;

            string who = r.UserName ?? r.UserSid ?? "?";
            string title = "Сессия " + (r.Luid ?? "?") + "  |  " + who + "  |  " + (r.AuthPackage ?? "?");
            string ruleStyle = r.HasSuspicious
                ? "red"
                : (r.IsUnknown
                    ? "yellow"
                    : (r.IsNotEvaluated ? "grey" : "green"));
            AnsiConsole.Write(new Rule("[bold]" + Markup.Escape(title) + "[/]")
                .LeftJustified().RuleStyle(ruleStyle));

            if (r.ReferenceOk)
            {
                AnsiConsole.MarkupLine("  Эталон: [green]" + Markup.Escape(r.ReferenceSource ?? "") + "[/]" +
                    "   групп: токен=[bold]" + r.TokenDomainGroupCount + "[/], эталон=[bold]" + r.ReferenceDomainGroupCount + "[/]");
            }
            else
            {
                string label = r.IsNotEvaluated ? "НЕ ОЦЕНИВАЛОСЬ" : "ОШИБКА";
                AnsiConsole.MarkupLine(
                    "  Эталон: [yellow]" + label + " (" +
                    Markup.Escape(r.ReferenceSource ?? "") + ")[/] — " +
                    Markup.Escape(r.ReferenceError ?? r.Reason.ToString()));
            }

            if (r.RuleIds.Count != 0)
                AnsiConsole.MarkupLine(
                    "  Правила: [bold]" +
                    Markup.Escape(String.Join(", ", r.RuleIds)) + "[/]");

            var shown = new List<DiffRow>();
            foreach (var row in r.Rows)
                if (_verbose || row.Kind != DiffKind.Match)
                    shown.Add(row);

            if (shown.Count == 0)
            {
                if (r.IsNotEvaluated)
                    AnsiConsole.MarkupLine("  [grey]Сессия пропущена политикой анализа.[/]");
                else if (r.IsUnknown)
                    AnsiConsole.MarkupLine("  [yellow]Анализ не завершён: авторитетный эталон недоступен.[/]");
                else
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
                "с расхождениями: [bold " + color + "]" + _suspiciousSessions + "[/]   " +
                "не определено: [bold yellow]" + _unknownSessions + "[/]   " +
                "не оценивалось: [grey]" + _notEvaluatedSessions + "[/]");

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
                catch (IOException ex)
                {
                    ReportHtmlFailure(ex);
                }
                catch (UnauthorizedAccessException ex)
                {
                    ReportHtmlFailure(ex);
                }
                catch (SecurityException ex)
                {
                    ReportHtmlFailure(ex);
                }
                catch (NotSupportedException ex)
                {
                    ReportHtmlFailure(ex);
                }
                catch (ArgumentException ex)
                {
                    ReportHtmlFailure(ex);
                }
            }
        }

        private static void ReportHtmlFailure(Exception exception)
        {
            AnsiConsole.MarkupLine(
                "[red]Не удалось сохранить HTML:[/] " +
                Markup.Escape(exception.Message));
        }
    }
}
