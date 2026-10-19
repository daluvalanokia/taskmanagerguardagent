using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TaskManagerGuardAgent
{
    /// <summary>User settings + allow/block lists, persisted as JSON next to the exe
    /// (or in %APPDATA%\TaskManagerGuardAgent if the exe folder is not writable).</summary>
    public class Config
    {
        public string VirusTotalApiKey { get; set; } = "";
        /// <summary>Seconds to wait on the permission dialog before auto-blocking. 0 = wait forever.</summary>
        public int AutoBlockSeconds { get; set; } = 45;
        /// <summary>When true, only prompt for interactive/elevated-looking launches and let known system processes through.</summary>
        public bool QuietSystemProcesses { get; set; } = true;
        public bool ProtectionEnabled { get; set; } = true;
        public bool PromptOncePerPath { get; set; } = true;

        /// <summary>Lower-cased exe paths the user has permanently allowed.</summary>
        public List<string> AllowlistPaths { get; set; } = new List<string>();
        /// <summary>SHA-256 hashes the user has permanently allowed.</summary>
        public List<string> AllowlistHashes { get; set; } = new List<string>();
        /// <summary>Lower-cased exe paths the user has permanently blocked.</summary>
        public List<string> BlocklistPaths { get; set; } = new List<string>();

        [JsonIgnore]
        public static string ConfigFolder { get; } = GetConfigFolder();

        private static string GetConfigFolder()
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string dir = Path.Combine(appData, "TaskManagerGuardAgent");
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static string ConfigPath => Path.Combine(ConfigFolder, "config.json");

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true
        };

        public static Config Load()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    var cfg = JsonSerializer.Deserialize<Config>(File.ReadAllText(ConfigPath), JsonOpts);
                    if (cfg != null) return cfg;
                }
            }
            catch { /* corrupt config -> fall through to defaults */ }
            return new Config();
        }

        public void Save()
        {
            File.WriteAllText(ConfigPath, JsonSerializer.Serialize(this, JsonOpts));
        }

        public bool IsAllowed(string exePath, string sha256)
        {
            if (!string.IsNullOrEmpty(exePath) &&
                AllowlistPaths.Contains(exePath.ToLowerInvariant()))
                return true;
            if (!string.IsNullOrEmpty(sha256) && AllowlistHashes.Contains(sha256))
                return true;
            return false;
        }

        public void AllowPath(string exePath)
        {
            if (string.IsNullOrEmpty(exePath)) return;
            var p = exePath.ToLowerInvariant();
            if (!AllowlistPaths.Contains(p)) AllowlistPaths.Add(p);
            Save();
        }

        public void AllowHash(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return;
            if (!AllowlistHashes.Contains(sha256)) AllowlistHashes.Add(sha256);
            Save();
        }

        public void BlockPath(string exePath)
        {
            if (string.IsNullOrEmpty(exePath)) return;
            var p = exePath.ToLowerInvariant();
            if (!BlocklistPaths.Contains(p)) BlocklistPaths.Add(p);
            Save();
        }

        public bool IsBlockedPath(string exePath)
        {
            if (string.IsNullOrEmpty(exePath)) return false;
            return BlocklistPaths.Contains(exePath.ToLowerInvariant());
        }

        public void UnblockPath(string exePath)
        {
            if (string.IsNullOrEmpty(exePath)) return;
            BlocklistPaths.Remove(exePath.ToLowerInvariant());
            Save();
        }
    }
}
