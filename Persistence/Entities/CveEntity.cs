namespace WindowsIncidentAnalyzer.Persistence.Entities;

public sealed class CveEntity
{
    public string CveId { get; set; } = string.Empty;

    public string? VendorProject { get; set; }

    public string? Product { get; set; }

    public string? VulnerabilityName { get; set; }

    public string? ShortDescription { get; set; }

    public string? RequiredAction { get; set; }

    public DateTime? DateAddedUtc { get; set; }

    public DateTime? DueDateUtc { get; set; }

    public string? KnownRansomwareUse { get; set; }

    public string? Notes { get; set; }

    public string Source { get; set; } = string.Empty;

    public DateTime ImportedUtc { get; set; }
}
