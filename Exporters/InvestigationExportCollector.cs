using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Exporters;

internal static class InvestigationExportCollector
{
    public static IReadOnlyList<long> CollectEventRowIds(InvestigationExport data)
    {
        var ids = new HashSet<long>();

        foreach (var finding in data.Findings)
        {
            foreach (var id in finding.RelatedEventRowIds)
            {
                if (id > 0)
                {
                    ids.Add(id);
                }
            }
        }

        foreach (var correlation in data.Correlations)
        {
            foreach (var id in correlation.RelatedEventRowIds)
            {
                if (id > 0)
                {
                    ids.Add(id);
                }
            }
        }

        foreach (var match in data.IocMatches)
        {
            if (match.EventRowId > 0)
            {
                ids.Add(match.EventRowId);
            }
        }

        foreach (var item in data.Timeline)
        {
            if (item.EventRowId > 0)
            {
                ids.Add(item.EventRowId);
            }
        }

        return ids.Count == 0 ? [] : ids.OrderBy(id => id).ToArray();
    }
}
