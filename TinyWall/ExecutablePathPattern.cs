using System;
using System.Collections.Generic;
using System.IO;

namespace pylorak.TinyWall
{
    public sealed class ExecutablePathPattern
    {
        public string Pattern { get; }
        public string RootPath { get; }
        public bool IncludeSubdirectories => Segments.Length > 1;
        private readonly string[] Segments;
        private readonly string RootPrefix;

        public static bool HasWildcards(string path)
        {
            return path.IndexOfAny(new[] { '*', '?' }) >= 0;
        }

        public ExecutablePathPattern(string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern) || pattern.Length > 4096)
                throw new ArgumentException("Specify a local executable path pattern.", nameof(pattern));

            var parts = pattern.Replace('/', '\\').Split('\\');
            if (parts.Length < 3 || parts[0].Length != 2 || parts[0][1] != ':'
                || !((parts[0][0] >= 'A' && parts[0][0] <= 'Z') || (parts[0][0] >= 'a' && parts[0][0] <= 'z')))
                throw new ArgumentException("Use an absolute local path with a fixed folder, not a drive-wide or network pattern.", nameof(pattern));

            int firstWildcard = -1;
            for (int i = 1; i < parts.Length; ++i)
            {
                string part = parts[i];
                if (string.IsNullOrEmpty(part) || part == "." || part == ".."
                    || part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal)
                    || part.IndexOfAny(new[] { ':', '<', '>', '"', '|', '\0' }) >= 0)
                    throw new ArgumentException("The path contains an invalid or ambiguous component.", nameof(pattern));
                foreach (char ch in part)
                    if (char.IsControl(ch))
                        throw new ArgumentException("Control characters are not supported in a path.", nameof(pattern));
                if (part.Contains("**") && part != "**")
                    throw new ArgumentException("Use ** only as a complete directory component.", nameof(pattern));
                if (firstWildcard < 0 && HasWildcards(part))
                    firstWildcard = i;
            }

            if (firstWildcard < 2)
                throw new ArgumentException("Anchor the wildcard below a fixed folder.", nameof(pattern));
            if (!parts[parts.Length - 1].EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("The final component must name or match .exe files.", nameof(pattern));

            RootPath = Path.GetFullPath(string.Join("\\", parts, 0, firstWildcard)).TrimEnd('\\');
            RootPrefix = RootPath + "\\";
            Segments = new string[parts.Length - firstWildcard];
            Array.Copy(parts, firstWildcard, Segments, 0, Segments.Length);
            Pattern = RootPrefix + string.Join("\\", Segments);
        }

        public bool Matches(string executablePath)
        {
            string path = executablePath.Replace('/', '\\');
            if (!path.StartsWith(RootPrefix, StringComparison.OrdinalIgnoreCase))
                return false;
            var components = path.Substring(RootPrefix.Length).Split('\\');
            foreach (string component in components)
                if (component.Length == 0 || component == "." || component == "..")
                    return false;

            // Dynamic programming keeps recursive ** matching bounded by the path length.
            var previous = new bool[components.Length + 1];
            previous[0] = true;
            foreach (string segment in Segments)
            {
                var current = new bool[components.Length + 1];
                if (segment == "**")
                {
                    current[0] = previous[0];
                    for (int j = 1; j <= components.Length; ++j)
                        current[j] = previous[j] || current[j - 1];
                }
                else
                {
                    for (int j = 1; j <= components.Length; ++j)
                        current[j] = previous[j - 1] && MatchesComponent(segment, components[j - 1]);
                }
                previous = current;
            }
            return previous[components.Length];
        }

        private static bool MatchesComponent(string pattern, string text)
        {
            int p = 0, t = 0, star = -1, retry = 0;
            while (t < text.Length)
            {
                if (p < pattern.Length && (pattern[p] == '?'
                    || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(text[t])))
                {
                    ++p; ++t;
                }
                else if (p < pattern.Length && pattern[p] == '*')
                {
                    star = p++;
                    retry = t;
                }
                else if (star >= 0)
                {
                    p = star + 1;
                    t = ++retry;
                }
                else
                    return false;
            }
            while (p < pattern.Length && pattern[p] == '*') ++p;
            return p == pattern.Length;
        }

        public HashSet<string> EnumerateExecutables()
        {
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!Directory.Exists(RootPath))
                return result;

            // Never follow junctions or symlinks into an unrelated folder.
            string? ancestor = RootPath;
            while (!string.IsNullOrEmpty(ancestor))
            {
                if ((File.GetAttributes(ancestor) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("A wildcard root may not traverse a reparse point: " + ancestor);
                ancestor = Path.GetDirectoryName(ancestor);
            }

            var pending = new Stack<string>();
            pending.Push(RootPath);
            while (pending.Count > 0)
            {
                string directory = pending.Pop();
                foreach (string file in Directory.GetFiles(directory, "*.exe", SearchOption.TopDirectoryOnly))
                    if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) == 0 && Matches(file))
                        result.Add(file);
                if (IncludeSubdirectories)
                    foreach (string child in Directory.GetDirectories(directory))
                        if (MatchesDirectoryPrefix(child) && (File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0)
                            pending.Push(child);
            }
            return result;
        }

        public bool MatchesDirectoryPrefix(string directoryPath)
        {
            if (!directoryPath.StartsWith(RootPrefix, StringComparison.OrdinalIgnoreCase))
                return false;
            int count = Segments.Length - 1;
            var states = new bool[count + 1];
            states[0] = true;
            void CloseRecursiveStates(bool[] positions)
            {
                for (int i = 0; i < count; ++i)
                    if (positions[i] && Segments[i] == "**") positions[i + 1] = true;
            }
            CloseRecursiveStates(states);
            foreach (string component in directoryPath.Substring(RootPrefix.Length).Split('\\'))
            {
                var next = new bool[count + 1];
                for (int i = 0; i < count; ++i)
                    if (states[i])
                    {
                        if (Segments[i] == "**") next[i] = true;
                        else if (MatchesComponent(Segments[i], component)) next[i + 1] = true;
                    }
                CloseRecursiveStates(next);
                states = next;
            }
            foreach (bool possible in states) if (possible) return true;
            return false;
        }
    }
}
