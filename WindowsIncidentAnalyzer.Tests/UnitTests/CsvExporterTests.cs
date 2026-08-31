using ClosedXML.Excel;
using WindowsIncidentAnalyzer.Exporters;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class CsvExporterTests
{
    [Fact]
    public async Task ExportAsync_WritesExcelWithBoldHeadersAndEnglishLabels()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wia-export-{Guid.NewGuid():N}.csv");
        try
        {
            var exporter = new CsvExporter();
            var data = new InvestigationExport
            {
                Findings =
                [
                    new SecurityFinding
                    {
                        Severity = DetectionSeverity.High,
                        RuleName = "TestRule",
                        Title = "Подозрительная активность",
                        Description = "Описание на\r\nрусском",
                        User = "Пользователь",
                        TimeUtc = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc),
                        RelatedEventRowIds = [7]
                    }
                ],
                Events =
                [
                    new WindowsEvent
                    {
                        Id = 7,
                        EventId = 4688,
                        LogName = "Security",
                        CommandLine = "powershell.exe -enc abc"
                    }
                ]
            };

            await exporter.ExportAsync(data, path, CancellationToken.None);

            var stem = Path.Combine(
                Path.GetDirectoryName(Path.GetFullPath(path))!,
                Path.GetFileNameWithoutExtension(path));
            var outputPath = stem + "-findings.xlsx";

            Assert.True(File.Exists(outputPath));
            Assert.True(File.Exists(stem + "-statistics.xlsx"));
            Assert.True(File.Exists(stem + "-events.xlsx"));

            using var workbook = new XLWorkbook(outputPath);
            var worksheet = workbook.Worksheet("Findings");

            Assert.True(worksheet.Row(1).Style.Font.Bold);
            Assert.Equal(XLAlignmentHorizontalValues.Center, worksheet.Row(1).Style.Alignment.Horizontal);
            Assert.Equal("Severity", worksheet.Cell(1, 1).GetString());
            Assert.True(FindHeaderColumn(worksheet, "Command Line") > 0);
            Assert.Equal("Подозрительная активность", FindColumnValueByHeader(worksheet, "Title", 2));
            Assert.Equal("Описание на русском", FindColumnValueByHeader(worksheet, "Description", 2));
            Assert.Equal("Пользователь", FindColumnValueByHeader(worksheet, "User", 2));
            Assert.Equal("powershell.exe -enc abc", FindColumnValueByHeader(worksheet, "Command Line", 2));
            Assert.Equal("2026-08-01 12:00:00", FindColumnValueByHeader(worksheet, "Time UTC", 2));
        }
        finally
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(directory))
            {
                var stem = Path.GetFileNameWithoutExtension(path);
                foreach (var file in Directory.EnumerateFiles(directory, stem + "-*"))
                {
                    File.Delete(file);
                }
            }
        }
    }

    private static int FindHeaderColumn(IXLWorksheet worksheet, string header)
    {
        var lastColumn = worksheet.LastColumnUsed()?.ColumnNumber() ?? 1;
        for (var col = 1; col <= lastColumn; col++)
        {
            if (worksheet.Cell(1, col).GetString() == header)
            {
                return col;
            }
        }

        return -1;
    }

    private static string FindColumnValueByHeader(IXLWorksheet worksheet, string header, int row)
    {
        var col = FindHeaderColumn(worksheet, header);
        return col > 0 ? worksheet.Cell(row, col).GetString() : string.Empty;
    }
}
