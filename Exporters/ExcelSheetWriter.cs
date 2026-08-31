using System.Reflection;
using ClosedXML.Excel;
using CsvHelper.Configuration;

namespace WindowsIncidentAnalyzer.Exporters;

internal static class ExcelSheetWriter
{
    public static Task WriteAsync<T>(
        string path,
        string sheetName,
        IEnumerable<T> rows,
        ClassMap<T> map,
        CancellationToken cancellationToken)
    {
        var materialized = rows.ToList();
        return Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(path, sheetName, materialized, map);
        }, cancellationToken);
    }

    private static void Write<T>(string path, string sheetName, IReadOnlyList<T> rows, ClassMap<T> map)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var columns = map.MemberMaps
            .OrderBy(m => m.Data.Index)
            .ThenBy(m => m.Data.Names.FirstOrDefault() ?? string.Empty, StringComparer.Ordinal)
            .ToList();

        using var workbook = new XLWorkbook();
        var safeSheetName = sheetName.Length <= 31 ? sheetName : sheetName[..31];
        var worksheet = workbook.Worksheets.Add(safeSheetName);

        for (var col = 0; col < columns.Count; col++)
        {
            var header = columns[col].Data.Names.FirstOrDefault()
                         ?? columns[col].Data.Member?.Name
                         ?? string.Empty;
            worksheet.Cell(1, col + 1).Value = header;
        }

        var headerRow = worksheet.Row(1);
        headerRow.Style.Font.Bold = true;
        headerRow.Style.Fill.BackgroundColor = XLColor.FromHtml("#E8EEF4");
        headerRow.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
        headerRow.Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;

        for (var rowIndex = 0; rowIndex < rows.Count; rowIndex++)
        {
            var record = rows[rowIndex];
            for (var col = 0; col < columns.Count; col++)
            {
                var value = GetMemberValue(record, columns[col].Data.Member);
                SetCellValue(worksheet.Cell(rowIndex + 2, col + 1), value);
            }
        }

        worksheet.SheetView.FreezeRows(1);
        if (rows.Count > 0)
        {
            worksheet.RangeUsed()?.SetAutoFilter();
        }

        foreach (var column in worksheet.ColumnsUsed())
        {
            column.AdjustToContents(1, 120);
            if (column.Width > 64)
            {
                column.Width = 64;
            }
        }

        workbook.SaveAs(path);
    }

    private static object? GetMemberValue<T>(T record, MemberInfo? member)
    {
        return member switch
        {
            PropertyInfo property => property.GetValue(record),
            FieldInfo field => field.GetValue(record),
            _ => null
        };
    }

    private static void SetCellValue(IXLCell cell, object? value)
    {
        if (value is null)
        {
            return;
        }

        switch (value)
        {
            case int i:
                cell.Value = i;
                break;
            case long l:
                cell.Value = l;
                break;
            case short s:
                cell.Value = s;
                break;
            case double d:
                cell.Value = d;
                break;
            case float f:
                cell.Value = f;
                break;
            case decimal m:
                cell.Value = m;
                break;
            case bool b:
                cell.Value = b;
                break;
            case DateTime dt:
                cell.Value = dt;
                break;
            case DateTimeOffset dto:
                cell.Value = dto.UtcDateTime;
                break;
            default:
                cell.Value = value.ToString() ?? string.Empty;
                break;
        }
    }
}
