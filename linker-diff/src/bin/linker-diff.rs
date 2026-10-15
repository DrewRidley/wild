fn main() -> anyhow::Result<()> {
    linker_diff::enable_diagnostics();

    let config = linker_diff::Config::from_env();
    let report = linker_diff::Report::from_config(config)?;

    // Printed on every run, including successful ones. "No differences detected" is only
    // meaningful in proportion to how much was actually inspected, so always say what wasn't.
    if let Some(gaps) = report.coverage_gap_report() {
        eprint!("{gaps}");
    }

    if report.has_problems() {
        println!("{report}");
        std::process::exit(1);
    } else {
        println!("No differences or validation failures detected");
    }

    if let Some(coverage) = report.coverage.as_ref() {
        println!("{coverage}");
    }

    Ok(())
}
