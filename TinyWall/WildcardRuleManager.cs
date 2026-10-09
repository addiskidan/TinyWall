using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;

namespace pylorak.TinyWall
{
    public sealed class WildcardRuleManager : IDisposable
    {
        private readonly Action Changed;
        private readonly Action<Exception> ReportError;
        private readonly Dictionary<string, FileSystemWatcher> Watchers = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<Guid, HashSet<string>> KnownBlocks = new();
        private readonly ConcurrentDictionary<string, byte> FailedWatchers = new(StringComparer.OrdinalIgnoreCase);
        private Dictionary<string, HashSet<string>> InstalledMatches = new(StringComparer.OrdinalIgnoreCase);
        private List<FirewallExceptionV3> PatternRules = new();
        private volatile bool Disposed;

        public WildcardRuleManager(Action changed, Action<Exception> reportError)
        {
            Changed = changed;
            ReportError = reportError;
        }

        private Dictionary<string, HashSet<string>> ReadMatches()
        {
            var matches = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var rule in PatternRules)
            {
                string pattern = ((ExecutableSubject)rule.Subject).ExecutablePath;
                if (matches.ContainsKey(pattern)) continue;
                try
                {
                    matches.Add(pattern, new ExecutablePathPattern(pattern).EnumerateExecutables());
                }
                catch (Exception e) when (e is ArgumentException || e is IOException || e is UnauthorizedAccessException)
                {
                    ReportError(e);
                    // Do not create an allow rule from an unreadable or malformed pattern.
                    matches.Add(pattern, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                }
            }
            return matches;
        }

        public List<FirewallExceptionV3> Expand(IEnumerable<FirewallExceptionV3> exceptions)
        {
            var exact = new List<FirewallExceptionV3>();
            PatternRules = new List<FirewallExceptionV3>();
            foreach (var rule in exceptions)
            {
                if (rule.Subject is ExecutableSubject executable && ExecutablePathPattern.HasWildcards(executable.ExecutablePath))
                {
                    if (rule.Subject is ServiceSubject)
                    {
                        ReportError(new ArgumentException("Wildcard Windows service subjects are not supported."));
                        continue;
                    }
                    PatternRules.Add(rule);
                }
                else
                    exact.Add(rule);
            }

            // Subscribe before the scan so an update during enumeration triggers another scan.
            RefreshWatchers();
            InstalledMatches = ReadMatches();
            var activeBlocks = new HashSet<Guid>();
            foreach (var rule in PatternRules)
            {
                string pattern = ((ExecutableSubject)rule.Subject).ExecutablePath;
                HashSet<string> paths = InstalledMatches[pattern];
                if (rule.Policy.PolicyType == PolicyType.HardBlock)
                {
                    activeBlocks.Add(rule.Id);
                    if (!KnownBlocks.TryGetValue(rule.Id, out var known))
                        KnownBlocks.Add(rule.Id, known = new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                    // Retain known block identities until the pattern rule itself is removed.
                    known.UnionWith(paths);
                    paths = known;
                }

                foreach (string path in paths)
                    exact.Add(new FirewallExceptionV3(new ExecutableSubject(path), rule.Policy)
                    {
                        Id = rule.Id,
                        Timer = rule.Timer,
                        CreationDate = rule.CreationDate,
                        ChildProcessesInherit = rule.ChildProcessesInherit
                    });
            }
            foreach (var id in new List<Guid>(KnownBlocks.Keys))
                if (!activeBlocks.Contains(id)) KnownBlocks.Remove(id);
            return exact;
        }

        public bool HasMembershipChanged()
        {
            RefreshWatchers();
            var current = ReadMatches();
            if (current.Count != InstalledMatches.Count) return true;
            foreach (var pair in current)
                if (!InstalledMatches.TryGetValue(pair.Key, out var old) || !old.SetEquals(pair.Value))
                    return true;
            return false;
        }

        private void RefreshWatchers()
        {
            foreach (string key in FailedWatchers.Keys)
                if (FailedWatchers.TryRemove(key, out _) && Watchers.TryGetValue(key, out var failed))
                {
                    failed.Dispose();
                    Watchers.Remove(key);
                }
            var wanted = new Dictionary<string, ExecutablePathPattern>(StringComparer.OrdinalIgnoreCase);
            foreach (var rule in PatternRules)
            {
                try
                {
                    var pattern = new ExecutablePathPattern(((ExecutableSubject)rule.Subject).ExecutablePath);
                    string key = pattern.RootPath + "|" + pattern.IncludeSubdirectories;
                    if (Directory.Exists(pattern.RootPath)) wanted[key] = pattern;
                }
                catch (ArgumentException e) { ReportError(e); }
            }
            foreach (string key in new List<string>(Watchers.Keys))
                if (!wanted.ContainsKey(key))
                {
                    Watchers[key].Dispose();
                    Watchers.Remove(key);
                }
            foreach (var pair in wanted)
            {
                if (Watchers.ContainsKey(pair.Key)) continue;
                FileSystemWatcher? watcher = null;
                try
                {
                    watcher = new FileSystemWatcher(pair.Value.RootPath)
                    {
                        IncludeSubdirectories = pair.Value.IncludeSubdirectories,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName
                    };
                    watcher.Created += OnChanged;
                    watcher.Deleted += OnChanged;
                    watcher.Renamed += OnChanged;
                    watcher.Error += OnError;
                    watcher.EnableRaisingEvents = true;
                    Watchers.Add(pair.Key, watcher);
                }
                catch (Exception e) when (e is ArgumentException || e is IOException || e is UnauthorizedAccessException)
                {
                    watcher?.Dispose();
                    ReportError(e);
                }
            }
        }

        private void OnChanged(object sender, FileSystemEventArgs args)
        {
            if (!Disposed) Changed();
        }

        private void OnError(object sender, ErrorEventArgs args)
        {
            if (!Disposed)
            {
                if (sender is FileSystemWatcher watcher)
                    FailedWatchers.TryAdd(watcher.Path + "|" + watcher.IncludeSubdirectories, 0);
                ReportError(args.GetException());
                Changed();
            }
        }

        public void Dispose()
        {
            Disposed = true;
            foreach (var watcher in Watchers.Values) watcher.Dispose();
            Watchers.Clear();
        }
    }
}
