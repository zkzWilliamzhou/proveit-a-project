---
name: anthropics-skill-spec
description: Reference for the Agent Skills SKILL.md format. Use when authoring a new skill folder, checking frontmatter, or explaining why a skill is or is not discovered.
---

# Agent Skills format reference

Source: `anthropics/skills` README, section "Creating a Basic Skill". This folder
is a derived, attributed reference, not a copy of a repository subtree. See
`docs/VENDOR_SKILLS.md`.

## Minimal structure

A skill is one folder containing `SKILL.md`. The file begins with YAML
frontmatter, then Markdown instructions.

The frontmatter requires exactly two fields:

- `name`: a unique identifier, lowercase letters, digits and hyphens. It must
  match the folder name.
- `description`: what the skill does and when to use it. This is the discovery
  signal, so it must be specific and written in third person.

Everything else is optional. Keep `SKILL.md` short and put detail in
`references/`, `scripts/` or `assets/` so the body loads only when the skill is
active.

## Minimal template

```markdown
---
name: my-skill-name
description: A clear description of what this skill does and when to use it
---

# My Skill Name

[Add your instructions here that the agent will follow when this skill is active]

## Examples

- Example usage 1
- Example usage 2

## Guidelines

- Guideline 1
- Guideline 2
```

## Validation checklist

- Frontmatter parses as YAML and contains `name` and `description`.
- `name` is `^[a-z0-9]+(-[a-z0-9]+)*$`, at most 64 characters, and equals the
  folder name.
- `description` names the task and the trigger condition, not a vague benefit.
- The body uses actionable instructions. Prefer MUST / SHOULD / NEVER over
  suggestions.
- No credentials, unpublished data or personal information appear in the skill.
- Scripts bundled with the skill are read before they are run.
