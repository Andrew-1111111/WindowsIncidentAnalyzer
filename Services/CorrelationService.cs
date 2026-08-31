using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class CorrelationService(
    IEventRepository eventRepository,
    IOptions<DetectionRulesOptions> options,
    IOptions<AnalyzerOptions> analyzerOptions,
    ILogger<CorrelationService> logger) : ICorrelationService
{
    public async Task<IReadOnlyList<EventCorrelation>> CorrelateAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        var ids = new[] { 4624, 4625, 4648, 4672, 4720, 4728, 4732, 4756, 4697, 4698, 4688, 7045, 4104, 1, 3 };
        var events = await eventRepository.GetByEventIdsAsync(ids, filter, cancellationToken);
        return Correlate(events);
    }

    public IReadOnlyList<EventCorrelation> Correlate(IEnumerable<WindowsEvent> events)
    {
        var list = events.OrderBy(e => e.TimeCreatedUtc).ToList();
        var window = TimeSpan.FromMinutes(Math.Max(1, options.Value.Correlation.CorrelationWindowMinutes));
        var analysis = analyzerOptions.Value.Analysis;
        var results = new List<EventCorrelation>();

        var correlators = new Func<List<WindowsEvent>, TimeSpan, IEnumerable<EventCorrelation>>[]
        {
            CompromisedPrivilegedAccount,
            SuspiciousAccountCreation,
            ScheduledTaskPersistence,
            PowerShellToNetwork,
            RemoteLogonToSuspiciousProcess,
            ServiceInstallationToProcess
        };

        if (analysis.EnableParallelAnalysis && correlators.Length > 1)
        {
            var bag = new ConcurrentBag<EventCorrelation>();
            var parallelOptions = ParallelAnalysis.CreateCpuBoundOptions(analysis);
            Parallel.ForEach(correlators, parallelOptions, correlator =>
            {
                foreach (var chain in correlator(list, window))
                {
                    bag.Add(chain);
                }
            });
            results.AddRange(bag);
        }
        else
        {
            foreach (var correlator in correlators)
            {
                results.AddRange(correlator(list, window));
            }
        }

        logger.LogInformation("Correlation produced {Count} chain(s)", results.Count);
        return results;
    }

    private static IEnumerable<EventCorrelation> CompromisedPrivilegedAccount(List<WindowsEvent> events, TimeSpan window)
    {
        var failures = events.Where(e => e.EventId == 4625).ToList();
        var successes = events.Where(e => e.EventId == 4624).ToList();
        var priv = events.Where(e => e.EventId == 4672).ToList();

        foreach (var group in failures.GroupBy(AccountIp))
        {
            var fails = group.OrderBy(e => e.TimeCreatedUtc).ToList();
            if (fails.Count < 5)
            {
                continue;
            }

            for (var i = 0; i < fails.Count; i++)
            {
                var cluster = fails.Skip(i).TakeWhile(e => e.TimeCreatedUtc - fails[i].TimeCreatedUtc <= window).ToList();
                if (cluster.Count < 5)
                {
                    continue;
                }

                var last = cluster[^1];
                var success = successes.FirstOrDefault(s =>
                    AccountIp(s) == group.Key &&
                    s.TimeCreatedUtc >= last.TimeCreatedUtc &&
                    s.TimeCreatedUtc <= last.TimeCreatedUtc + window);

                if (success == null)
                {
                    continue;
                }

                var special = priv.FirstOrDefault(p =>
                    string.Equals(p.User, success.TargetUserName ?? success.User, StringComparison.OrdinalIgnoreCase) &&
                    p.TimeCreatedUtc >= success.TimeCreatedUtc &&
                    p.TimeCreatedUtc <= success.TimeCreatedUtc + window);

                if (special == null)
                {
                    continue;
                }

                var related = cluster.Concat([success, special]).ToList();
                yield return new EventCorrelation
                {
                    Scenario = "FailedLogonsThenPrivilegedSuccess",
                    Title = "Potential compromised privileged account",
                    Interpretation =
                        "A burst of failed logons was followed by a successful authentication and assignment of special privileges (4625 x N → 4624 → 4672).",
                    Severity = DetectionSeverity.Critical,
                    TimeUtc = special.TimeCreatedUtc,
                    User = success.TargetUserName ?? success.User,
                    ComputerName = success.ComputerName,
                    SourceIpAddress = success.SourceIpAddress,
                    Details = $"failures={cluster.Count}; account={group.Key}",
                    RelatedEventRowIds = related.Select(e => e.Id).Where(id => id > 0).ToList()
                };
                break;
            }
        }
    }

    private static IEnumerable<EventCorrelation> SuspiciousAccountCreation(List<WindowsEvent> events, TimeSpan window)
    {
        var created = events.Where(e => e.EventId == 4720).ToList();
        var groups = events.Where(e => e.EventId is 4728 or 4732).ToList();
        var logons = events.Where(e => e.EventId == 4624).ToList();

        foreach (var create in created)
        {
            var name = create.TargetUserName;
            if (string.IsNullOrEmpty(name))
            {
                continue;
            }

            var groupAdd = groups.FirstOrDefault(g =>
                g.TimeCreatedUtc >= create.TimeCreatedUtc &&
                g.TimeCreatedUtc <= create.TimeCreatedUtc + window &&
                Contains(g, name));

            if (groupAdd == null)
            {
                continue;
            }

            var logon = logons.FirstOrDefault(l =>
                string.Equals(l.TargetUserName, name, StringComparison.OrdinalIgnoreCase) &&
                l.TimeCreatedUtc >= groupAdd.TimeCreatedUtc &&
                l.TimeCreatedUtc <= groupAdd.TimeCreatedUtc + window);

            if (logon == null)
            {
                continue;
            }

            yield return new EventCorrelation
            {
                Scenario = "AccountCreatedThenPrivilegedThenLogon",
                Title = "Potential suspicious account creation and privilege assignment",
                Interpretation = "A new account was created, added to a group, and then used to log on within the correlation window (4720 → 4728/4732 → 4624).",
                Severity = DetectionSeverity.High,
                TimeUtc = logon.TimeCreatedUtc,
                User = name,
                ComputerName = create.ComputerName,
                Details = $"creator={create.User}; newUser={name}",
                RelatedEventRowIds = new[] { create.Id, groupAdd.Id, logon.Id }.Where(id => id > 0).ToList()
            };
        }
    }

    private static IEnumerable<EventCorrelation> ScheduledTaskPersistence(List<WindowsEvent> events, TimeSpan window)
    {
        var tasks = events.Where(e => e.EventId == 4698).ToList();
        var processes = events.Where(e => e.EventId == 4688 || IsSysmon(e, 1)).ToList();

        foreach (var task in tasks)
        {
            var xml = task.CommandLine ?? task.RawXml ?? string.Empty;
            var process = processes.FirstOrDefault(p =>
                p.TimeCreatedUtc >= task.TimeCreatedUtc &&
                p.TimeCreatedUtc <= task.TimeCreatedUtc + window &&
                ProcessMatchesTask(p, xml, task.TaskName));

            if (process == null)
            {
                continue;
            }

            yield return new EventCorrelation
            {
                Scenario = "ScheduledTaskThenProcess",
                Title = "Potential persistence mechanism",
                Interpretation = "A scheduled task was created and a matching process started shortly afterwards (4698 → 4688/Sysmon 1).",
                Severity = DetectionSeverity.High,
                TimeUtc = process.TimeCreatedUtc,
                User = task.User,
                ComputerName = task.ComputerName,
                Details = ProcessRelatedDetails(task, process),
                RelatedEventRowIds = new[] { task.Id, process.Id }.Where(id => id > 0).ToList()
            };
        }
    }

    private static string ProcessRelatedDetails(WindowsEvent task, WindowsEvent process) =>
        $"task={task.TaskName}; process={process.ProcessName}; image={process.ProcessPath}";

    private static IEnumerable<EventCorrelation> PowerShellToNetwork(List<WindowsEvent> events, TimeSpan window)
    {
        var scripts = events.Where(e => e.EventId == 4104).ToList();
        var processes = events.Where(e => IsSysmon(e, 1)).ToList();
        var network = events.Where(e => IsSysmon(e, 3)).ToList();

        foreach (var script in scripts)
        {
            var proc = processes.FirstOrDefault(p =>
                p.TimeCreatedUtc >= script.TimeCreatedUtc.AddMinutes(-1) &&
                p.TimeCreatedUtc <= script.TimeCreatedUtc + window &&
                IsPowerShellProcess(p) &&
                SameHost(script, p));

            if (proc == null)
            {
                continue;
            }

            var conn = network.FirstOrDefault(n =>
                SameProcess(proc, n) &&
                n.TimeCreatedUtc >= proc.TimeCreatedUtc &&
                n.TimeCreatedUtc <= proc.TimeCreatedUtc + window);

            if (conn == null)
            {
                continue;
            }

            yield return new EventCorrelation
            {
                Scenario = "PowerShellThenProcessThenNetwork",
                Title = "PowerShell activity followed by process creation and network connection",
                Interpretation = "Script-block logging, Sysmon process creation, and a Sysmon network connection were linked by process identifiers and time (4104 → Sysmon 1 → Sysmon 3).",
                Severity = DetectionSeverity.High,
                TimeUtc = conn.TimeCreatedUtc,
                User = proc.User ?? script.User,
                ComputerName = proc.ComputerName,
                SourceIpAddress = conn.DestinationIpAddress ?? conn.SourceIpAddress,
                Details = $"pid={proc.ProcessId}; guid={proc.ProcessGuid}; dest={conn.DestinationIpAddress}:{conn.DestinationPort}",
                RelatedEventRowIds = new[] { script.Id, proc.Id, conn.Id }.Where(id => id > 0).ToList()
            };
        }
    }

    private static IEnumerable<EventCorrelation> RemoteLogonToSuspiciousProcess(List<WindowsEvent> events, TimeSpan window)
    {
        var remoteLogons = events
            .Where(e => e.EventId == 4624 && e.LogonType is 3 or 8 or 9 or 10)
            .Where(e => !string.IsNullOrWhiteSpace(e.SourceIpAddress) && e.SourceIpAddress != "-")
            .ToList();
        var processes = events
            .Where(e => e.EventId == 4688 || IsSysmon(e, 1))
            .Where(IsRemoteExecutionProcess)
            .ToList();

        foreach (var logon in remoteLogons)
        {
            var process = processes.FirstOrDefault(candidate =>
                SameHost(logon, candidate) &&
                candidate.TimeCreatedUtc >= logon.TimeCreatedUtc &&
                candidate.TimeCreatedUtc <= logon.TimeCreatedUtc + window &&
                AccountsCompatible(logon, candidate));
            if (process == null)
            {
                continue;
            }

            yield return new EventCorrelation
            {
                Scenario = "RemoteLogonThenSuspiciousProcess",
                Title = "Remote authentication followed by suspicious process execution",
                Interpretation = "A network/RDP authentication was followed by a command shell, script host, or common proxy-execution binary on the same host.",
                Severity = DetectionSeverity.High,
                TimeUtc = process.TimeCreatedUtc,
                User = logon.TargetUserName ?? logon.User,
                ComputerName = logon.ComputerName,
                SourceIpAddress = logon.SourceIpAddress,
                Details = $"logonType={logon.LogonType}; process={process.ProcessName}; commandLine={process.CommandLine}",
                RelatedEventRowIds = new[] { logon.Id, process.Id }.Where(id => id > 0).ToList()
            };
        }
    }

    private static IEnumerable<EventCorrelation> ServiceInstallationToProcess(List<WindowsEvent> events, TimeSpan window)
    {
        var services = events.Where(e => e.EventId is 4697 or 7045).ToList();
        var processes = events.Where(e => e.EventId == 4688 || IsSysmon(e, 1)).ToList();

        foreach (var service in services)
        {
            var image = service.ProcessPath ?? service.CommandLine ?? string.Empty;
            var process = processes.FirstOrDefault(candidate =>
                SameHost(service, candidate) &&
                candidate.TimeCreatedUtc >= service.TimeCreatedUtc &&
                candidate.TimeCreatedUtc <= service.TimeCreatedUtc + window &&
                ((!string.IsNullOrWhiteSpace(candidate.ProcessPath) &&
                  image.Contains(candidate.ProcessPath, StringComparison.OrdinalIgnoreCase)) ||
                 (!string.IsNullOrWhiteSpace(candidate.ProcessName) &&
                  image.Contains(candidate.ProcessName, StringComparison.OrdinalIgnoreCase))));
            if (process == null)
            {
                continue;
            }

            yield return new EventCorrelation
            {
                Scenario = "ServiceInstalledThenProcess",
                Title = "New service followed by matching process execution",
                Interpretation = "A newly installed service was followed by execution of its configured image, consistent with service-based persistence or lateral movement.",
                Severity = DetectionSeverity.High,
                TimeUtc = process.TimeCreatedUtc,
                User = service.User,
                ComputerName = service.ComputerName,
                Details = $"service={service.ServiceName}; image={image}; process={process.ProcessName}",
                RelatedEventRowIds = new[] { service.Id, process.Id }.Where(id => id > 0).ToList()
            };
        }
    }

    private static string AccountIp(WindowsEvent evt) =>
        $"{(evt.TargetUserName ?? evt.User ?? string.Empty).ToLowerInvariant()}|{(evt.SourceIpAddress ?? string.Empty).ToLowerInvariant()}";

    private static bool Contains(WindowsEvent evt, string value) =>
        (evt.TargetUserName?.Contains(value, StringComparison.OrdinalIgnoreCase) ?? false) ||
        (evt.RawXml?.Contains(value, StringComparison.OrdinalIgnoreCase) ?? false) ||
        evt.GetProperty("MemberName").Contains(value, StringComparison.OrdinalIgnoreCase);

    private static bool IsSysmon(WindowsEvent evt, int eventId) =>
        evt.EventId == eventId && evt.ProviderName?.Contains("Sysmon", StringComparison.OrdinalIgnoreCase) == true;

    private static bool IsPowerShellProcess(WindowsEvent evt) =>
        evt.ProcessName?.Contains("powershell", StringComparison.OrdinalIgnoreCase) == true ||
        evt.ProcessPath?.Contains("powershell", StringComparison.OrdinalIgnoreCase) == true;

    private static bool IsRemoteExecutionProcess(WindowsEvent evt)
    {
        var name = evt.ProcessName ?? string.Empty;
        return new[]
        {
            "cmd.exe", "powershell.exe", "pwsh.exe", "wmic.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "psexec.exe"
        }.Any(candidate => name.Equals(candidate, StringComparison.OrdinalIgnoreCase));
    }

    private static bool AccountsCompatible(WindowsEvent logon, WindowsEvent process)
    {
        var logonUser = logon.TargetUserName ?? logon.User;
        var processUser = process.TargetUserName ?? process.User;
        return string.IsNullOrWhiteSpace(processUser) ||
               string.IsNullOrWhiteSpace(logonUser) ||
               string.Equals(logonUser, processUser, StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameHost(WindowsEvent a, WindowsEvent b) =>
        string.IsNullOrEmpty(a.ComputerName) || string.IsNullOrEmpty(b.ComputerName) ||
        string.Equals(a.ComputerName, b.ComputerName, StringComparison.OrdinalIgnoreCase);

    private static bool SameProcess(WindowsEvent process, WindowsEvent other)
    {
        if (!string.IsNullOrEmpty(process.ProcessGuid) && !string.IsNullOrEmpty(other.ProcessGuid) &&
            string.Equals(process.ProcessGuid, other.ProcessGuid, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (process.ProcessId is { } pid && other.ProcessId == pid && SameHost(process, other))
        {
            return true;
        }

        return !string.IsNullOrEmpty(process.ProcessName) &&
               string.Equals(process.ProcessName, other.ProcessName, StringComparison.OrdinalIgnoreCase) &&
               SameHost(process, other);
    }

    private static bool ProcessMatchesTask(WindowsEvent process, string taskXml, string? taskName)
    {
        if (!string.IsNullOrEmpty(process.ProcessPath) && taskXml.Contains(process.ProcessPath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrEmpty(process.ProcessName) && taskXml.Contains(process.ProcessName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return !string.IsNullOrEmpty(taskName) &&
               (process.CommandLine?.Contains(taskName, StringComparison.OrdinalIgnoreCase) ?? false);
    }
}
