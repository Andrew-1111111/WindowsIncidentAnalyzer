using Microsoft.EntityFrameworkCore;
using WindowsIncidentAnalyzer.Persistence.Entities;
using WindowsIncidentAnalyzer.Infrastructure;

namespace WindowsIncidentAnalyzer.Persistence;

public sealed class InvestigationDbContext(DbContextOptions<InvestigationDbContext> options) : DbContext(options)
{
    public DbSet<EventEntity> Events => Set<EventEntity>();

    public DbSet<FindingEntity> Findings => Set<FindingEntity>();

    public DbSet<IocEntity> Iocs => Set<IocEntity>();

    public DbSet<IncidentEntity> Incidents => Set<IncidentEntity>();

    public DbSet<CorrelationEntity> Correlations => Set<CorrelationEntity>();

    public DbSet<CveEntity> Cves => Set<CveEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var isoConverter = new Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<DateTime, string>(
            v => DateTimeParser.Iso(v),
            v => DateTimeParser.Parse(v) ?? DateTime.MinValue);

        var nullableIsoConverter = new Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<DateTime?, string?>(
            v => v.HasValue ? DateTimeParser.Iso(v.Value) : null,
            v => DateTimeParser.Parse(v));

        modelBuilder.Entity<EventEntity>(entity =>
        {
            entity.ToTable("Events");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).ValueGeneratedOnAdd();
            entity.Property(e => e.TimeCreatedUtc).HasConversion(isoConverter).IsRequired();
            entity.Property(e => e.EventId).IsRequired();
            entity.Property(e => e.CompletenessScore).IsRequired().HasDefaultValue(0);
            entity.HasIndex(e => e.EventKey).IsUnique().HasDatabaseName("UX_Events_EventKey");
            entity.HasIndex(e => e.TimeCreatedUtc).HasDatabaseName("IX_Events_TimeCreatedUtc");
            entity.HasIndex(e => e.EventId).HasDatabaseName("IX_Events_EventId");
            entity.HasIndex(e => e.User).HasDatabaseName("IX_Events_User");
            entity.HasIndex(e => e.SourceIpAddress).HasDatabaseName("IX_Events_SourceIp");
            entity.HasIndex(e => e.ProcessName).HasDatabaseName("IX_Events_ProcessName");
            entity.HasIndex(e => e.ComputerName).HasDatabaseName("IX_Events_Host");
            entity.HasIndex(e => e.TargetUserName).HasDatabaseName("IX_Events_TargetUser");
            entity.HasIndex(e => e.ProcessGuid).HasDatabaseName("IX_Events_ProcessGuid");
            entity.HasIndex(e => e.ScriptBlockHash).HasDatabaseName("IX_Events_ScriptBlockHash");
        });

        modelBuilder.Entity<FindingEntity>(entity =>
        {
            entity.ToTable("Findings");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).ValueGeneratedOnAdd();
            entity.Property(e => e.RuleName).IsRequired();
            entity.Property(e => e.Title).IsRequired();
            entity.Property(e => e.Severity).IsRequired();
            entity.Property(e => e.TimeUtc).HasConversion(isoConverter).IsRequired();
            entity.Property(e => e.CreatedUtc).HasConversion(isoConverter).IsRequired();
            entity.HasIndex(e => e.Severity).HasDatabaseName("IX_Findings_Severity");
            entity.HasIndex(e => e.TimeUtc).HasDatabaseName("IX_Findings_TimeUtc");
        });

        modelBuilder.Entity<IocEntity>(entity =>
        {
            entity.ToTable("Iocs");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).ValueGeneratedOnAdd();
            entity.Property(e => e.Type).IsRequired();
            entity.Property(e => e.Value).IsRequired();
            entity.Property(e => e.ImportedUtc).HasConversion(isoConverter).IsRequired();
            entity.HasIndex(e => new { e.Type, e.Value }).IsUnique();
            entity.HasIndex(e => e.Type).HasDatabaseName("IX_Iocs_Type");
        });

        modelBuilder.Entity<IncidentEntity>(entity =>
        {
            entity.ToTable("Incidents");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).ValueGeneratedOnAdd();
            entity.Property(e => e.Title).IsRequired();
            entity.Property(e => e.CreatedUtc).HasConversion(isoConverter).IsRequired();
            entity.Property(e => e.EventsAnalyzed).IsRequired();
            entity.Property(e => e.FindingsCritical).IsRequired();
            entity.Property(e => e.FindingsHigh).IsRequired();
            entity.Property(e => e.FindingsMedium).IsRequired();
            entity.Property(e => e.FindingsLow).IsRequired();
            entity.Property(e => e.FindingsInfo).IsRequired();
        });

        modelBuilder.Entity<CorrelationEntity>(entity =>
        {
            entity.ToTable("Correlations");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).ValueGeneratedOnAdd();
            entity.Property(e => e.Scenario).IsRequired();
            entity.Property(e => e.Title).IsRequired();
            entity.Property(e => e.Severity).IsRequired();
            entity.Property(e => e.TimeUtc).HasConversion(isoConverter).IsRequired();
            entity.Property(e => e.CreatedUtc).HasConversion(isoConverter).IsRequired();
        });

        modelBuilder.Entity<CveEntity>(entity =>
        {
            entity.ToTable("Cves");
            entity.HasKey(e => e.CveId);
            entity.Property(e => e.CveId).IsRequired();
            entity.Property(e => e.Source).IsRequired();
            entity.Property(e => e.DateAddedUtc).HasConversion(nullableIsoConverter);
            entity.Property(e => e.DueDateUtc).HasConversion(nullableIsoConverter);
            entity.Property(e => e.ImportedUtc).HasConversion(isoConverter).IsRequired();
            entity.HasIndex(e => e.Product).HasDatabaseName("IX_Cves_Product");
        });
    }
}
