using System.CommandLine;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Commands;

public static class IocCommand
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static Command Create(IServiceProvider services)
    {
        var command = new Command("ioc", "Import, update from public threat feeds, and scan indicators of compromise.");

        var fileArg = new Argument<string>("file")
        {
            Description = "Path to a JSON array of IOC objects."
        };
        var import = new Command("import", "Import IOC indicators from JSON.");
        import.Arguments.Add(fileArg);
        import.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var path = parse.GetValue(fileArg) ?? throw new ArgumentException("IOC file path is required.");
                var iocs = await ReadIocFileAsync(path, token);
                await services.GetRequiredService<IIocRepository>().ImportAsync(iocs, token);
                AnsiConsole.MarkupLine($"[green]Imported {iocs.Count:N0} IOC(s)[/] from {Markup.Escape(path)}.");
            }, ct);
        });

        var saveOption = new Option<string?>("--save")
        {
            Description = "Also write the downloaded indicators to a JSON file (default: samples/indicators.json)."
        };
        var update = new Command("update", "Download public defensive IOC feeds (abuse.ch, Emerging Threats, DigitalSide, OpenPhish, and others) and import them.");
        update.Options.Add(saveOption);
        update.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                IReadOnlyList<Ioc> iocs = [];
                await AnsiConsole.Status()
                    .AutoRefresh(true)
                    .Spinner(Spinner.Known.Dots)
                    .StartAsync("Downloading public IOC feeds...", async _ =>
                    {
                        var progress = new Progress<string>(line => _.Status(line));
                        iocs = await services.GetRequiredService<IIocFeedService>().DownloadAsync(token, progress);
                    });

                AnsiConsole.WriteLine();
                await services.GetRequiredService<IIocRepository>().ReplaceAllAsync(iocs, token);

                var savePath = parse.GetValue(saveOption)
                               ?? Path.Combine(Directory.GetCurrentDirectory(), "samples", "indicators.json");
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(savePath))!);
                var payload = iocs.Select(i => new IocDto
                {
                    Type = i.Type,
                    Value = i.Value,
                    Comment = i.Comment,
                    Source = i.Source
                }).ToList();
                await File.WriteAllTextAsync(savePath, JsonSerializer.Serialize(payload, JsonOptions), token);

                var byType = iocs.GroupBy(i => i.Type).OrderBy(g => g.Key);
                AnsiConsole.MarkupLine($"[green]Imported {iocs.Count:N0} unique IOC(s)[/] from public feeds.");
                foreach (var group in byType)
                {
                    AnsiConsole.MarkupLine($"  {Markup.Escape(group.Key)}: {group.Count():N0}");
                }

                AnsiConsole.MarkupLine($"JSON saved to {Markup.Escape(Path.GetFullPath(savePath))}");
            }, ct);
        });

        var scan = new Command("scan", "Match imported IOCs against collected events.");
        scan.Options.Add(SharedCliOptions.Hours);
        scan.Options.Add(SharedCliOptions.From);
        scan.Options.Add(SharedCliOptions.To);
        scan.Options.Add(SharedCliOptions.Date);
        scan.Options.Add(SharedCliOptions.Limit);
        scan.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var analyzer = services.GetRequiredService<Microsoft.Extensions.Options.IOptions<WindowsIncidentAnalyzer.Configuration.AnalyzerOptions>>().Value;
                var filter = SharedCliOptions.BuildFilter(parse, analyzer, defaultHoursWhenMissing: false);
                var matches = await services.GetRequiredService<IIocDetectionService>().ScanAsync(filter, token);
                if (matches.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No IOC matches. Import or run 'ioc update', then collect events.[/]");
                    return;
                }

                ConsolePresenter.IocMatches(matches);
            }, ct);
        });

        command.Subcommands.Add(import);
        command.Subcommands.Add(update);
        command.Subcommands.Add(scan);
        return command;
    }

    private static async Task<List<Ioc>> ReadIocFileAsync(string path, CancellationToken cancellationToken)
    {
        var json = await File.ReadAllTextAsync(path, cancellationToken);
        List<IocDto> items;
        try
        {
            items = JsonSerializer.Deserialize<List<IocDto>>(json, JsonOptions) ?? [];
        }
        catch (JsonException ex)
        {
            throw new ArgumentException($"IOC JSON is invalid: {ex.Message}", ex);
        }

        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ip", "ipv4", "ipv6", "domain", "hash", "sha256", "sha1", "md5", "filename", "file", "url", "user"
        };

        var iocs = new List<Ioc>();
        foreach (var item in items)
        {
            if (string.IsNullOrWhiteSpace(item.Type) || string.IsNullOrWhiteSpace(item.Value))
            {
                continue;
            }

            if (!allowed.Contains(item.Type))
            {
                continue;
            }

            iocs.Add(new Ioc
            {
                Type = item.Type,
                Value = item.Value,
                Comment = item.Comment,
                Source = item.Source ?? Path.GetFileName(path),
                ImportedUtc = DateTime.UtcNow
            });
        }

        return iocs;
    }

    private sealed class IocDto
    {
        public string? Type { get; set; }

        public string? Value { get; set; }

        public string? Comment { get; set; }

        public string? Source { get; set; }
    }
}
