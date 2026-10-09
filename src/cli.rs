//! Command-line interface definition.

use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Pdf,
    Both,
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "easy-ad",
    version,
    about = "Fast, automated Active Directory enumeration and attack-path scanner",
    long_about = "easy-ad automates the AD recon workflow a pentester would normally run \
manually with NetExec (nxc): host discovery, credential validation, BloodHound \
collection and attack-path checks, with a single command."
)]
pub struct Cli {
    /// Target IP, comma-separated IPs, CIDR subnet, or hostname (required; or via --config)
    #[arg(short, long, default_value = "")]
    pub target: String,

    /// AD domain name (required; or via --config)
    #[arg(short, long, default_value = "")]
    pub domain: String,

    /// Username
    #[arg(short, long)]
    pub username: Option<String>,

    /// Password
    #[arg(short, long)]
    pub password: Option<String>,

    /// NTLM hash (LM:NT or bare NT) - alternative to --password
    #[arg(long, conflicts_with = "password")]
    pub hash: Option<String>,

    /// Use Kerberos authentication
    #[arg(short = 'k', long)]
    pub kerberos: bool,

    /// Domain Controller IP (auto-discovered via DNS SRV if omitted)
    #[arg(long)]
    pub dc: Option<String>,

    /// Enable BloodHound CE data collection
    #[arg(long)]
    pub bloodhound: bool,

    /// BloodHound output directory (default: <output>/bloodhound)
    #[arg(long)]
    pub bh_output: Option<String>,

    /// Run all attack-path checks plus protocol checks
    #[arg(long)]
    pub all_checks: bool,

    /// Run Kerberoasting
    #[arg(long)]
    pub kerberoast: bool,

    /// Run AS-REP Roasting
    #[arg(long)]
    pub asreproast: bool,

    /// Run Pre-Windows-2000 computer account check
    #[arg(long)]
    pub pre2k: bool,

    /// Run coercion vulnerability scan (PetitPotam, DFSCoerce, PrinterBug, ...)
    #[arg(long)]
    pub coerce: bool,

    /// Attempt gMSA password extraction
    #[arg(long)]
    pub gmsa: bool,

    /// Enumerate SMB shares and permissions
    #[arg(long)]
    pub shares: bool,

    /// Check WinRM access
    #[arg(long)]
    pub winrm: bool,

    /// Check RDP access
    #[arg(long)]
    pub rdp: bool,

    /// Check MSSQL access
    #[arg(long)]
    pub mssql: bool,

    /// Output directory (default: ./easy-ad-output)
    #[arg(short, long, default_value = "./easy-ad-output")]
    pub output: String,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Both)]
    pub format: OutputFormat,

    /// Number of concurrent threads
    #[arg(short = 'T', long, default_value_t = 10)]
    pub threads: usize,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    /// Include raw hashes/tickets in the PDF report (they are always written to disk separately)
    #[arg(long)]
    pub include_hashes: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Disable NetExec auto-install prompt; fail gracefully instead
    #[arg(long)]
    pub no_nxc_install: bool,

    /// Optional TOML config file; command-line flags take precedence over it
    #[arg(long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,
}

impl Cli {
    /// Effective per-check flags with --all-checks applied.
    pub fn checks(&self) -> EffectiveChecks {
        let all = self.all_checks;
        EffectiveChecks {
            kerberoast: self.kerberoast || all,
            asreproast: self.asreproast || all,
            pre2k: self.pre2k || all,
            coerce: self.coerce || all,
            gmsa: self.gmsa || all,
            shares: self.shares || all,
            winrm: self.winrm || all,
            rdp: self.rdp || all,
            mssql: self.mssql || all,
        }
    }

    /// Output file format selection.
    pub fn want_json(&self) -> bool {
        matches!(self.format, OutputFormat::Json | OutputFormat::Both)
    }

    pub fn want_pdf(&self) -> bool {
        matches!(self.format, OutputFormat::Pdf | OutputFormat::Both)
    }
}

/// Concrete set of checks to run after applying `--all-checks`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EffectiveChecks {
    pub kerberoast: bool,
    pub asreproast: bool,
    pub pre2k: bool,
    pub coerce: bool,
    pub gmsa: bool,
    pub shares: bool,
    pub winrm: bool,
    pub rdp: bool,
    pub mssql: bool,
}

/// Partial, all-optional mirror of [`Cli`] used for config file loading.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigFile {
    pub target: Option<String>,
    pub domain: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub hash: Option<String>,
    pub kerberos: Option<bool>,
    pub dc: Option<String>,
    pub bloodhound: Option<bool>,
    pub bh_output: Option<String>,
    pub all_checks: Option<bool>,
    pub kerberoast: Option<bool>,
    pub asreproast: Option<bool>,
    pub pre2k: Option<bool>,
    pub coerce: Option<bool>,
    pub gmsa: Option<bool>,
    pub shares: Option<bool>,
    pub winrm: Option<bool>,
    pub rdp: Option<bool>,
    pub mssql: Option<bool>,
    pub output: Option<String>,
    pub format: Option<String>,
    pub threads: Option<usize>,
    pub timeout: Option<u64>,
    pub include_hashes: Option<bool>,
    pub verbose: Option<bool>,
    pub no_nxc_install: Option<bool>,
}

/// Apply a config file to `cli`, only for flags NOT given on the command line.
pub fn apply_config(
    cli: &mut Cli,
    matches: &clap::ArgMatches,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    use clap::parser::ValueSource;
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read config file {}: {}", path.display(), e))?;
    let cfg: ConfigFile = toml::from_str(&text)
        .map_err(|e| anyhow::anyhow!("cannot parse config file {}: {}", path.display(), e))?;

    let from_cli = |name: &str| matches.value_source(name) == Some(ValueSource::CommandLine);

    macro_rules! fill {
        ($field:ident) => {
            if !from_cli(stringify!($field)) {
                if let Some(v) = cfg.$field {
                    cli.$field = v;
                }
            }
        };
    }
    macro_rules! fill_opt {
        ($field:ident) => {
            if !from_cli(stringify!($field)) {
                if let Some(v) = cfg.$field {
                    cli.$field = Some(v);
                }
            }
        };
    }

    fill!(target);
    fill!(domain);
    fill_opt!(username);
    fill_opt!(password);
    fill_opt!(hash);
    fill!(kerberos);
    fill_opt!(dc);
    fill!(bloodhound);
    fill_opt!(bh_output);
    fill!(all_checks);
    fill!(kerberoast);
    fill!(asreproast);
    fill!(pre2k);
    fill!(coerce);
    fill!(gmsa);
    fill!(shares);
    fill!(winrm);
    fill!(rdp);
    fill!(mssql);
    fill!(output);
    fill!(threads);
    fill!(timeout);
    fill!(include_hashes);
    fill!(verbose);
    fill!(no_nxc_install);

    if !from_cli("format") {
        if let Some(f) = cfg.format {
            cli.format = match f.as_str() {
                "json" => OutputFormat::Json,
                "pdf" => OutputFormat::Pdf,
                "both" => OutputFormat::Both,
                other => anyhow::bail!("invalid format '{}' in config file", other),
            };
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_minimal_invocation() {
        let cli = Cli::try_parse_from(["easy-ad", "-t", "192.168.1.0/24", "-d", "corp.local"])
            .unwrap();
        assert_eq!(cli.target, "192.168.1.0/24");
        assert_eq!(cli.domain, "corp.local");
        assert_eq!(cli.threads, 10);
        assert_eq!(cli.timeout, 10);
        assert!(cli.want_json() && cli.want_pdf());
    }

    #[test]
    fn all_checks_enables_everything() {
        let cli = Cli::try_parse_from([
            "easy-ad", "-t", "10.0.0.1", "-d", "corp.local", "--all-checks",
        ])
        .unwrap();
        let c = cli.checks();
        assert!(c.kerberoast && c.asreproast && c.pre2k && c.coerce && c.gmsa);
        assert!(c.shares && c.winrm && c.rdp && c.mssql);
    }

    #[test]
    fn hash_conflicts_with_password() {
        let res = Cli::try_parse_from([
            "easy-ad", "-t", "10.0.0.1", "-d", "corp.local", "-p", "x", "--hash", "aa:bb",
        ]);
        assert!(res.is_err());
    }

    #[test]
    fn command_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn config_file_fills_unset_flags_and_cli_wins() {
        use clap::{CommandFactory, FromArgMatches};
        let dir = std::env::temp_dir().join("easy-ad-test-config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "target = \"10.0.0.0/24\"\ndomain = \"corp.local\"\nthreads = 42\nkerberoast = true\nformat = \"pdf\"\n",
        )
        .unwrap();

        // No CLI flags: everything comes from the config file.
        let m = Cli::command().get_matches_from(["easy-ad", "--config", path.to_str().unwrap()]);
        let mut cli = Cli::from_arg_matches(&m).unwrap();
        super::apply_config(&mut cli, &m, &path).unwrap();
        assert_eq!(cli.target, "10.0.0.0/24");
        assert_eq!(cli.domain, "corp.local");
        assert_eq!(cli.threads, 42);
        assert!(cli.kerberoast);
        assert!(cli.want_pdf() && !cli.want_json());

        // CLI flag beats the config file.
        let m2 = Cli::command().get_matches_from([
            "easy-ad", "--config", path.to_str().unwrap(), "-t", "192.168.0.1", "-T", "7",
        ]);
        let mut cli2 = Cli::from_arg_matches(&m2).unwrap();
        super::apply_config(&mut cli2, &m2, &path).unwrap();
        assert_eq!(cli2.target, "192.168.0.1");
        assert_eq!(cli2.threads, 7);
        assert_eq!(cli2.domain, "corp.local");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
