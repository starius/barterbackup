//! Generate CLI documentation artifacts from the shared clap command trees.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use bbcli::Args;
use bbd::Config;
use clap::{Arg, ArgAction, Command, CommandFactory};
use clap_complete::shells::{Bash, Elvish, Fish, PowerShell, Zsh};
use clap_complete::Generator;

const DOCS_DIR: &str = "docs/cli";
const MAN_DIR: &str = "man";
const COMPLETIONS_DIR: &str = "completions";

fn main() -> Result<()> {
    let cli = generator_command();
    let matches = cli.get_matches();
    let workspace_root = find_workspace_root()?;
    let check = matches.get_flag("check");
    let root = workspace_root.as_path();

    if check {
        verify_generated_outputs(root)
    } else {
        generate_outputs(root)
    }
}

fn generator_command() -> Command {
    Command::new("cli-docs")
        .about("Generate completions, man pages, and Markdown manuals")
        .arg(
            Arg::new("check")
                .long("check")
                .help("Fail if checked-in generated CLI docs are stale")
                .action(ArgAction::SetTrue),
        )
}

fn find_workspace_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .context("resolve workspace root")
}

fn generate_outputs(root: &Path) -> Result<()> {
    let outputs = render_outputs();
    write_outputs(root, &outputs)
}

fn verify_generated_outputs(root: &Path) -> Result<()> {
    let outputs = render_outputs();

    for output in outputs {
        let expected = root.join(&output.relative_path);
        let current = fs::read_to_string(&expected)
            .with_context(|| format!("read generated CLI artifact {}", expected.display()))?;
        if current != output.contents {
            bail!(
                "generated CLI artifact {} is stale; run `make cli-docs`",
                output.relative_path.display()
            );
        }
    }

    Ok(())
}

#[derive(Clone)]
struct GeneratedOutput {
    relative_path: PathBuf,
    contents: String,
}

fn write_outputs(root: &Path, outputs: &[GeneratedOutput]) -> Result<()> {
    for output in outputs {
        let path = root.join(&output.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(&path, &output.contents).with_context(|| format!("write {}", path.display()))?;
    }

    Ok(())
}

fn render_outputs() -> Vec<GeneratedOutput> {
    let mut outputs = Vec::new();
    outputs.extend(render_tool_outputs("bbcli", Args::command));
    outputs.extend(render_tool_outputs("bbd", Config::command));
    outputs
}

fn render_tool_outputs<F>(name: &str, command_builder: F) -> Vec<GeneratedOutput>
where
    F: Fn() -> Command + Copy,
{
    let mut outputs = Vec::new();
    let command = command_builder();
    outputs.push(GeneratedOutput {
        relative_path: PathBuf::from(DOCS_DIR).join(format!("{name}.md")),
        contents: render_markdown_manual(command.clone()),
    });
    outputs.push(GeneratedOutput {
        relative_path: PathBuf::from(MAN_DIR).join(format!("{name}.1")),
        contents: render_man_page(command.clone()),
    });

    for (shell_name, contents) in render_completions(name, visible_completion_command(command)) {
        outputs.push(GeneratedOutput {
            relative_path: PathBuf::from(COMPLETIONS_DIR).join(format!("{name}.{shell_name}")),
            contents,
        });
    }

    outputs
}

fn render_completions(name: &str, command: Command) -> Vec<(&'static str, String)> {
    vec![
        ("bash", render_completion(name, command.clone(), Bash)),
        ("elvish", render_completion(name, command.clone(), Elvish)),
        ("fish", render_completion(name, command.clone(), Fish)),
        ("ps1", render_completion(name, command.clone(), PowerShell)),
        ("zsh", render_completion(name, command, Zsh)),
    ]
}

fn leak_str(value: impl Into<String>) -> &'static str {
    Box::leak(value.into().into_boxed_str())
}

fn visible_completion_command(command: Command) -> Command {
    let mut visible = Command::new(leak_str(command.get_name()))
        .args(
            command
                .get_arguments()
                .filter(|argument| !argument.is_hide_set())
                .cloned(),
        )
        .subcommands(
            command
                .get_subcommands()
                .filter(|subcommand| !subcommand.is_hide_set())
                .cloned()
                .map(visible_completion_command),
        );

    if let Some(about) = command.get_about() {
        visible = visible.about(about.clone());
    }
    if let Some(long_about) = command.get_long_about() {
        visible = visible.long_about(long_about.clone());
    }
    if let Some(version) = command.get_version() {
        visible = visible.version(leak_str(version));
    }
    if let Some(long_version) = command.get_long_version() {
        visible = visible.long_version(leak_str(long_version));
    }
    if let Some(heading) = command.get_subcommand_help_heading() {
        visible = visible.subcommand_help_heading(leak_str(heading.to_string()));
    }
    if let Some(value_name) = command.get_subcommand_value_name() {
        visible = visible.subcommand_value_name(leak_str(value_name.to_string()));
    }
    if command.is_arg_required_else_help_set() {
        visible = visible.arg_required_else_help(true);
    }
    if command.is_args_conflicts_with_subcommands_set() {
        visible = visible.args_conflicts_with_subcommands(true);
    }
    if command.is_disable_help_flag_set() {
        visible = visible.disable_help_flag(true);
    }
    if command.is_disable_help_subcommand_set() {
        visible = visible.disable_help_subcommand(true);
    }
    if command.is_disable_version_flag_set() {
        visible = visible.disable_version_flag(true);
    }
    if command.is_multicall_set() {
        visible = visible.multicall(true);
    }
    if command.is_next_line_help_set() {
        visible = visible.next_line_help(true);
    }
    if command.is_no_binary_name_set() {
        visible = visible.no_binary_name(true);
    }
    if command.is_propagate_version_set() {
        visible = visible.propagate_version(true);
    }
    if command.is_subcommand_negates_reqs_set() {
        visible = visible.subcommand_negates_reqs(true);
    }
    if command.is_subcommand_precedence_over_arg_set() {
        visible = visible.subcommand_precedence_over_arg(true);
    }
    if command.is_subcommand_required_set() {
        visible = visible.subcommand_required(true);
    }

    visible
}

fn render_completion<G>(name: &str, mut command: Command, generator: G) -> String
where
    G: Generator,
{
    let mut output = Vec::new();
    clap_complete::generate(generator, &mut command, name, &mut output);
    String::from_utf8(output).expect("completion output is UTF-8")
}

fn render_man_page(command: Command) -> String {
    let mut buffer = Vec::new();
    clap_mangen::Man::new(command)
        .render(&mut buffer)
        .expect("render man page");
    String::from_utf8(buffer).expect("man page output is UTF-8")
}

fn render_markdown_manual(command: Command) -> String {
    let mut output = String::new();
    let command_path = command.get_name().to_string();
    render_markdown_command(&command, &command_path, &mut output, 1);
    output
}

fn render_markdown_command(
    command: &Command,
    command_path: &str,
    output: &mut String,
    level: usize,
) {
    let heading = "#".repeat(level);
    let section_heading = "#".repeat(level + 1);
    output.push_str(&format!("{heading} `{command_path}`\n\n"));

    if let Some(about) = command.get_about() {
        output.push_str(&format!("{about}\n\n"));
    }

    if let Some(long_about) = command.get_long_about() {
        if Some(long_about) != command.get_about() {
            output.push_str(&format!("{long_about}\n\n"));
        }
    }

    output.push_str(&format!("{section_heading} Usage\n\n"));
    output.push_str("```text\n");
    output.push_str(&render_usage(command, command_path));
    output.push_str("\n```\n\n");

    let visible_arguments = collect_visible_arguments(command);
    if !visible_arguments.is_empty() {
        output.push_str(&format!("{section_heading} Options\n\n"));
        for argument in visible_arguments {
            output.push_str(&render_argument_markdown(argument));
        }
        output.push('\n');
    }

    let visible_subcommands: Vec<_> = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .collect();
    if !visible_subcommands.is_empty() {
        output.push_str(&format!("{section_heading} Subcommands\n\n"));
        for subcommand in &visible_subcommands {
            let about = subcommand
                .get_about()
                .or_else(|| subcommand.get_long_about())
                .map(|text| text.to_string())
                .unwrap_or_default();
            output.push_str(&format!(
                "- `{}`{}{}\n",
                subcommand.get_name(),
                if about.is_empty() { "" } else { ": " },
                about
            ));
        }
        output.push('\n');

        for subcommand in visible_subcommands {
            let subcommand_path = format!("{command_path} {}", subcommand.get_name());
            render_markdown_command(subcommand, &subcommand_path, output, level + 1);
        }
    }
}

fn render_usage(command: &Command, command_path: &str) -> String {
    let mut clone = command.clone();
    let mut usage = Vec::new();
    clone.write_long_help(&mut usage).expect("render help");
    let help = String::from_utf8(usage).expect("help output is UTF-8");
    let usage_block = help
        .lines()
        .skip_while(|line| !line.starts_with("Usage:"))
        .take_while(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    let command_name = command.get_name();
    usage_block.replacen(
        &format!("Usage: {command_name}"),
        &format!("Usage: {command_path}"),
        1,
    )
}

fn collect_visible_arguments(command: &Command) -> Vec<&Arg> {
    command
        .get_arguments()
        .filter(|argument| !argument.is_hide_set())
        .collect()
}

fn render_argument_markdown(argument: &Arg) -> String {
    let mut line = String::new();
    line.push_str("- `");
    line.push_str(&render_argument_signature(argument));
    line.push('`');

    if let Some(help) = argument.get_long_help().or_else(|| argument.get_help()) {
        line.push_str(": ");
        line.push_str(&help.to_string());
    }

    let mut extras = Vec::new();
    if let Some(env) = argument.get_env() {
        extras.push(format!("env: `{}`", env.to_string_lossy()));
    }
    if let Some(defaults) = argument.get_default_values().first() {
        extras.push(format!("default: `{}`", defaults.to_string_lossy()));
    }
    if !extras.is_empty() {
        line.push_str(" (");
        line.push_str(&extras.join(", "));
        line.push(')');
    }

    line.push('\n');
    line
}

fn render_argument_signature(argument: &Arg) -> String {
    let mut parts = Vec::new();

    if let Some(short) = argument.get_short() {
        parts.push(format!("-{short}"));
    }
    if let Some(long) = argument.get_long() {
        parts.push(format!("--{long}"));
    }
    if parts.is_empty() {
        parts.push(argument.get_id().to_string());
    }

    let mut signature = parts.join(", ");
    if argument.get_action().takes_values() {
        let value_name = argument
            .get_value_names()
            .and_then(|names| names.first().cloned())
            .map(|name| name.to_string())
            .unwrap_or_else(|| argument.get_id().to_string().to_uppercase());
        signature.push(' ');
        signature.push('<');
        signature.push_str(&value_name);
        signature.push('>');
    }

    signature
}

#[cfg(test)]
mod tests {
    use super::{render_outputs, verify_generated_outputs};

    #[test]
    fn generated_outputs_exclude_hidden_test_flags() {
        let rendered = render_outputs();
        let bbd_markdown = rendered
            .iter()
            .find(|output| output.relative_path.to_string_lossy() == "docs/cli/bbd.md")
            .expect("bbd markdown output");
        let bbcli_markdown = rendered
            .iter()
            .find(|output| output.relative_path.to_string_lossy() == "docs/cli/bbcli.md")
            .expect("bbcli markdown output");
        let bbd_completions: Vec<_> = rendered
            .iter()
            .filter(|output| {
                output
                    .relative_path
                    .to_string_lossy()
                    .starts_with("completions/bbd.")
            })
            .collect();
        let bbcli_completions: Vec<_> = rendered
            .iter()
            .filter(|output| {
                output
                    .relative_path
                    .to_string_lossy()
                    .starts_with("completions/bbcli.")
            })
            .collect();

        assert!(bbd_markdown.contents.contains("--arti-config"));
        assert!(!bbd_markdown.contents.contains("--test-clock"));
        assert!(!bbd_markdown.contents.contains("--disable-maintenance"));
        assert!(!bbd_markdown
            .contents
            .contains("--peer-metadata-flush-delay-secs"));
        assert!(bbcli_markdown.contents.contains("`peer`"));
        assert!(!bbcli_markdown.contents.contains("export-built-in"));
        assert!(!bbd_completions.is_empty());
        assert!(!bbcli_completions.is_empty());
        for completion in bbd_completions {
            assert!(!completion.contents.contains("--test-clock"));
            assert!(!completion.contents.contains("--disable-maintenance"));
            assert!(!completion
                .contents
                .contains("--peer-metadata-flush-delay-secs"));
        }
        for completion in bbcli_completions {
            assert!(!completion.contents.contains("export-built-in"));
        }
    }

    #[test]
    fn checked_in_outputs_are_current() {
        let root = super::find_workspace_root().expect("workspace root");
        verify_generated_outputs(&root).expect("generated outputs are current");
    }
}
