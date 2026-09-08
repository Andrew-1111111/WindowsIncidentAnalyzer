using WindowsIncidentAnalyzer.Mitre;
using WindowsIncidentAnalyzer.Repositories;
using WindowsIncidentAnalyzer.Services;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class MitreAttackStixParserTests
{
    private const string SampleBundle = """
        {
          "type": "bundle",
          "objects": [
            {
              "type": "x-mitre-tactic",
              "name": "Discovery",
              "x_mitre_shortname": "discovery",
              "external_references": [
                {
                  "source_name": "mitre-attack",
                  "external_id": "TA0007",
                  "url": "https://attack.mitre.org/tactics/TA0007/"
                }
              ]
            },
            {
              "type": "attack-pattern",
              "name": "System Owner/User Discovery",
              "external_references": [
                {
                  "source_name": "mitre-attack",
                  "external_id": "T1033",
                  "url": "https://attack.mitre.org/techniques/T1033/"
                }
              ],
              "kill_chain_phases": [
                { "kill_chain_name": "mitre-attack", "phase_name": "discovery" }
              ]
            }
          ]
        }
        """;

    [Fact]
    public void Parse_ReadsTacticsAndTechniques()
    {
        var catalog = MitreAttackStixParser.Parse(SampleBundle);

        Assert.Single(catalog.Tactics);
        Assert.Equal("discovery", catalog.Tactics[0].ShortName);
        Assert.Single(catalog.Techniques);
        Assert.Equal("T1033", catalog.Techniques[0].ExternalId);
    }

    [Fact]
    public async Task Enricher_ResolvesTechniqueAndTacticNames()
    {
        var catalog = MitreAttackStixParser.Parse(SampleBundle);
        var repository = new MitreAttackRepository();
        await repository.ReplaceAsync(catalog.Tactics, catalog.Techniques, CancellationToken.None);

        var enricher = new MitreAttackEnrichmentService(repository);
        var context = new Models.FindingContext
        {
            MitreTechnique = "attack.t1033",
            MitreTactic = "attack.discovery"
        };

        enricher.Enrich(context);

        Assert.Equal("System Owner/User Discovery", context.MitreTechniqueName);
        Assert.Equal("Discovery", context.MitreTacticName);
        Assert.Contains("attack.mitre.org/techniques/T1033", context.MitreUrl);
    }
}

public sealed class CisaKevParserTests
{
    private const string SampleFeed = """
        {
          "vulnerabilities": [
            {
              "cveID": "CVE-2024-1234",
              "vendorProject": "Example",
              "product": "Widget",
              "vulnerabilityName": "Example Widget RCE",
              "dateAdded": "2024-01-01",
              "shortDescription": "Example vulnerability.",
              "requiredAction": "Apply updates.",
              "dueDate": "2024-02-01",
              "knownRansomwareCampaignUse": "Known",
              "notes": "Test note"
            }
          ]
        }
        """;

    [Fact]
    public void Parse_ReadsCveRecords()
    {
        var records = CisaKevParser.Parse(SampleFeed, "test");

        var record = Assert.Single(records);
        Assert.Equal("CVE-2024-1234", record.CveId);
        Assert.Equal("Example Widget RCE", record.VulnerabilityName);
    }

    [Fact]
    public void CveDetectionService_MatchesKnownCveInEventText()
    {
        var records = CisaKevParser.Parse(SampleFeed, "test");
        var repository = new TestCveRepository(records);
        var service = new CveDetectionService(
            new EmptyEventRepository(),
            repository,
            Microsoft.Extensions.Options.Options.Create(new Configuration.AnalyzerOptions()),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CveDetectionService>.Instance);

        var matches = service.Scan(
        [
            new Models.WindowsEvent
            {
                Id = 9,
                EventId = 4688,
                TimeCreatedUtc = DateTime.UtcNow,
                CommandLine = "installer.exe /cve CVE-2024-1234"
            }
        ],
        records.ToDictionary(r => r.CveId, StringComparer.OrdinalIgnoreCase));

        Assert.Single(matches);
        Assert.Equal("CVE-2024-1234", matches[0].CveId);
    }

    private sealed class TestCveRepository(IReadOnlyList<Models.CveRecord> records) : Repositories.ICveRepository
    {
        public int Count => records.Count;

        public Task<IReadOnlyList<Models.CveRecord>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult(records);

        public Task ReplaceAllAsync(IReadOnlyList<Models.CveRecord> replacement, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class EmptyEventRepository : Repositories.IEventRepository
    {
        public Task<int> InsertBatchAsync(IReadOnlyList<Models.WindowsEvent> events, CancellationToken cancellationToken) =>
            Task.FromResult(0);

        public Task<IReadOnlyList<Models.WindowsEvent>> QueryAsync(Models.EventQueryFilter filter, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<Models.WindowsEvent>>([]);

        public Task<int> CountAsync(Models.EventQueryFilter? filter, CancellationToken cancellationToken) =>
            Task.FromResult(0);

        public Task<IReadOnlyList<Models.WindowsEvent>> GetByEventIdsAsync(
            IReadOnlyList<int> eventIds,
            Models.EventQueryFilter? filter,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<Models.WindowsEvent>>([]);

        public Task<IReadOnlyDictionary<long, Models.WindowsEvent>> GetByRowIdsAsync(
            IReadOnlyList<long> rowIds,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyDictionary<long, Models.WindowsEvent>>(new Dictionary<long, Models.WindowsEvent>());
    }
}
