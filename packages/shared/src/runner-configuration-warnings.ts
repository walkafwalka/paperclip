export interface AgentConfigurationWarning {
  code: "runner_option_ignored" | "runner_option_conditional" | "protected_environment_variable";
  field: string;
  message: string;
}

// Only obsolete tuning/features belong here. Permission, filesystem, network,
// command and credential settings must retain their existing validation.
// `chrome` is not listed: it stays in the configuration, see CLAUDE_CONDITIONAL_OPTIONS.
const CLAUDE_IGNORED_OPTIONS = {
  maxTurnsPerRun: "Max turns per run",
  warmHandleIdleMs: "Warm handle idle timeout",
  acpWarmHandleIdleMs: "ACP warm handle idle timeout",
} as const;

// Kept in the configuration, but effective only under the stated condition.
// The warning says so, because this function cannot see the connection or the
// instance setting.
const CLAUDE_CONDITIONAL_OPTIONS = {
  chrome: "Chrome integration (chrome) works on Paperclip Runner only with a Claude subscription connection while the instance setting for full run scope is on. Otherwise it is ignored. The agent can still run.",
} as const;

export function normalizeClaudeRunnerOptions(config: Record<string, unknown>): {
  config: Record<string, unknown>;
  warnings: AgentConfigurationWarning[];
} {
  const normalized = { ...config };
  const warnings: AgentConfigurationWarning[] = [];
  for (const [field, label] of Object.entries(CLAUDE_IGNORED_OPTIONS)) {
    const value = config[field];
    if (value !== undefined && value !== null && value !== false && value !== "" && value !== 0
      && !(Array.isArray(value) && value.length === 0)) {
      warnings.push({ code: "runner_option_ignored", field,
        message: `${label} (${field}) is not supported by Paperclip Runner and is ignored. The agent can still run.` });
    }
    delete normalized[field];
  }
  for (const [field, message] of Object.entries(CLAUDE_CONDITIONAL_OPTIONS)) {
    if (config[field] === true) warnings.push({ code: "runner_option_conditional", field, message });
  }
  return { config: normalized, warnings };
}
