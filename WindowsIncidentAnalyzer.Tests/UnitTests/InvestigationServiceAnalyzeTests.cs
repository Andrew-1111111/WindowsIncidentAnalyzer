using Microsoft.Extensions.Logging.Abstractions;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Sigma.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class InvestigationServiceAnalyzeTests
{
    [Fact]
    public async Task AnalyzeAsync_LoadsThreatIntel_RunsDetectors_EnrichesMitre_ScansIocAndCve()
    {
        var events = new StubEventRepository(3);
        var findings = new StubFindingRepository();
        var correlations = new StubCorrelationRepository();
        var incidents = new StubIncidentRepository();
        var detection = new StubSuspiciousActivityService();
        var correlation = new StubCorrelationService();
        var iocs = new StubIocDetectionService();
        var cves = new StubCveDetectionService();
        var cveDatabase = new StubCveDatabaseService();
        var sigma = new StubSigmaRuleService();
        var mitre = new StubMitreAttackService();
        var mitreEnrichment = new StubMitreEnrichmentService();

        var service = new InvestigationService(
            events,
            findings,
            correlations,
            incidents,
            detection,
            correlation,
            iocs,
            cves,
            cveDatabase,
            sigma,
            mitre,
            mitreEnrichment,
            NullLogger<InvestigationService>.Instance);

        var summary = await service.AnalyzeAsync(new EventQueryFilter { Limit = 100 }, CancellationToken.None);

        Assert.True(sigma.EnsureLoadedCalled);
        Assert.True(mitre.EnsureLoadedCalled);
        Assert.True(cveDatabase.EnsureLoadedCalled);
        Assert.True(detection.AnalyzeCalled);
        Assert.True(mitreEnrichment.EnrichCalled);
        Assert.True(iocs.ScanCalled);
        Assert.True(cves.ScanCalled);
        Assert.True(correlation.CorrelateCalled);
        Assert.Single(summary.Findings);
        Assert.Single(summary.IocMatches);
        Assert.Single(summary.CveMatches);
    }

    private sealed class StubEventRepository(int count) : Repositories.IEventRepository
    {
        public Task<int> CountAsync(EventQueryFilter? filter, CancellationToken cancellationToken) =>
            Task.FromResult(count);

        public Task<int> InsertBatchAsync(IReadOnlyList<WindowsEvent> events, CancellationToken cancellationToken) =>
            Task.FromResult(0);

        public Task<IReadOnlyList<WindowsEvent>> QueryAsync(EventQueryFilter filter, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<WindowsEvent>>([]);

        public Task<IReadOnlyList<WindowsEvent>> GetByEventIdsAsync(
            IReadOnlyList<int> eventIds,
            EventQueryFilter? filter,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<WindowsEvent>>([]);

        public Task<IReadOnlyDictionary<long, WindowsEvent>> GetByRowIdsAsync(
            IReadOnlyList<long> rowIds,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyDictionary<long, WindowsEvent>>(new Dictionary<long, WindowsEvent>());
    }

    private sealed class StubFindingRepository : Repositories.IFindingRepository
    {
        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task InsertManyAsync(IReadOnlyList<SecurityFinding> findings, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<SecurityFinding>> GetAllAsync(int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SecurityFinding>>([]);
    }

    private sealed class StubCorrelationRepository : Repositories.ICorrelationRepository
    {
        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task InsertManyAsync(IReadOnlyList<EventCorrelation> correlations, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<EventCorrelation>> GetAllAsync(int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<EventCorrelation>>([]);
    }

    private sealed class StubIncidentRepository : Repositories.IIncidentRepository
    {
        public Task<long> InsertAsync(Incident incident, CancellationToken cancellationToken) => Task.FromResult(1L);

        public Task<Incident?> GetLatestAsync(CancellationToken cancellationToken) => Task.FromResult<Incident?>(null);
    }

    private sealed class StubSuspiciousActivityService : ISuspiciousActivityService
    {
        public bool AnalyzeCalled { get; private set; }

        public Task<IReadOnlyList<SecurityFinding>> AnalyzeAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
        {
            AnalyzeCalled = true;
            return Task.FromResult<IReadOnlyList<SecurityFinding>>(
            [
                new SecurityFinding
                {
                    RuleName = "SigmaRules",
                    Title = "[Sigma] Test",
                    Severity = DetectionSeverity.Medium,
                    TimeUtc = DateTime.UtcNow,
                    Context = new FindingContext { MitreTechnique = "attack.t1033" }
                }
            ]);
        }
    }

    private sealed class StubCorrelationService : ICorrelationService
    {
        public bool CorrelateCalled { get; private set; }

        public IReadOnlyList<EventCorrelation> Correlate(IEnumerable<WindowsEvent> events) => [];

        public Task<IReadOnlyList<EventCorrelation>> CorrelateAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
        {
            CorrelateCalled = true;
            return Task.FromResult<IReadOnlyList<EventCorrelation>>([]);
        }
    }

    private sealed class StubIocDetectionService : IIocDetectionService
    {
        public bool ScanCalled { get; private set; }

        public Task<IReadOnlyList<IocMatch>> ScanAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
        {
            ScanCalled = true;
            return Task.FromResult<IReadOnlyList<IocMatch>>(
            [
                new IocMatch { IocType = "ip", IocValue = "1.2.3.4", EventRowId = 1, EventId = 3 }
            ]);
        }

        public IReadOnlyList<IocMatch> Scan(IEnumerable<WindowsEvent> events, IEnumerable<Ioc> iocs) => [];
    }

    private sealed class StubCveDetectionService : ICveDetectionService
    {
        public bool ScanCalled { get; private set; }

        public Task<IReadOnlyList<CveMatch>> ScanAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
        {
            ScanCalled = true;
            return Task.FromResult<IReadOnlyList<CveMatch>>(
            [
                new CveMatch { CveId = "CVE-2024-1234", EventRowId = 2, EventId = 4688 }
            ]);
        }
    }

    private sealed class StubCveDatabaseService : ICveDatabaseService
    {
        public bool EnsureLoadedCalled { get; private set; }

        public int Count => 1;

        public Task EnsureLoadedAsync(CancellationToken cancellationToken)
        {
            EnsureLoadedCalled = true;
            return Task.CompletedTask;
        }

        public Task<int> LoadFromFileAsync(string path, CancellationToken cancellationToken) => Task.FromResult(1);

        public Task<int> UpdateFromCisaKevAsync(CancellationToken cancellationToken) => Task.FromResult(1);
    }

    private sealed class StubSigmaRuleService : ISigmaRuleService
    {
        public bool EnsureLoadedCalled { get; private set; }

        public Task EnsureLoadedAsync(CancellationToken cancellationToken)
        {
            EnsureLoadedCalled = true;
            return Task.CompletedTask;
        }

        public Task<int> LoadFromDirectoryAsync(string directory, CancellationToken cancellationToken) => Task.FromResult(0);

        public Task<int> UpdateFromSigmaHqAsync(CancellationToken cancellationToken) => Task.FromResult(0);

        public Task<int> UpdateFromHayabusaRulesAsync(CancellationToken cancellationToken) => Task.FromResult(0);

        public IReadOnlyList<SigmaRule> GetRules() => [];
    }

    private sealed class StubMitreAttackService : IMitreAttackService
    {
        public bool EnsureLoadedCalled { get; private set; }

        public Task EnsureLoadedAsync(CancellationToken cancellationToken)
        {
            EnsureLoadedCalled = true;
            return Task.CompletedTask;
        }

        public Task<int> LoadFromFileAsync(string path, CancellationToken cancellationToken) => Task.FromResult(0);

        public Task<int> UpdateFromMitreCtiAsync(CancellationToken cancellationToken) => Task.FromResult(0);

        public IReadOnlyList<MitreAttackTechnique> GetTechniques() => [];

        public IReadOnlyList<MitreAttackTactic> GetTactics() => [];

        public bool TryGetTechnique(string techniqueId, out MitreAttackTechnique technique)
        {
            technique = null!;
            return false;
        }

        public bool TryGetTactic(string shortName, out MitreAttackTactic tactic)
        {
            tactic = null!;
            return false;
        }
    }

    private sealed class StubMitreEnrichmentService : IMitreAttackEnrichmentService
    {
        public bool EnrichCalled { get; private set; }

        public void Enrich(FindingContext context) => EnrichCalled = true;

        public void Enrich(IEnumerable<SecurityFinding> findings)
        {
            EnrichCalled = true;
            foreach (var finding in findings)
            {
                Enrich(finding.Context);
            }
        }
    }
}
