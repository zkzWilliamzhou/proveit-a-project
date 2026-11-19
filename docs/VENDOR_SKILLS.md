# Vendored GitHub skills

The build installed the requested public skill sets into `skills/`. They are documentation and procedural instructions, not executable code loaded by proveit. Each folder keeps its upstream attribution; `skills/stop-slop/LICENSE` is the upstream MIT license.

Direct `git clone` of `github.com` was refused by the build network (HTTP 403). Public raw `README.md` files, public raw skill files and indexed copies were used instead. Where a full raw skill file could not be retrieved, the folder below is an explicitly attributed derived reference rather than a repository subtree. That limitation is recorded here instead of being hidden.

| Upstream | In `skills/` | Used for |
| --- | --- | --- |
| [anthropics/skills](https://github.com/anthropics/skills) | `anthropics-skill-spec` | SKILL.md frontmatter, folder layout and validation rules for the agent roster. Derived from the upstream README section "Creating a Basic Skill". |
| [obra/superpowers](https://github.com/obra/superpowers) | `brainstorming`, `verification-before-completion`, `systematic-debugging`, `test-driven-development`, `writing-plans`, `requesting-code-review`, `subagent-driven-development` | ideation, evidence-before-claims rule, debug loop, TDD, review gate |
| [mattpocock/skills](https://github.com/mattpocock/skills) | `improve-codebase-architecture`, `codebase-design`, `code-review`, `tdd`, `grilling`, `grill-me` | deletion test, deepening, module/depth/seam vocabulary, architecture pass |
| [vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills) | `writing-guidelines` | README and docs review. This skill fetches rules from `vercel-labs/writing-guidelines` at review time; those rules are not vendored. |
| [hardikpandya/stop-slop](https://github.com/hardikpandya/stop-slop) | `stop-slop` | prose cleanup, with its MIT license and reference files |
| [tomerose/stop-slop](https://github.com/tomerose/stop-slop) | not vendored | cross-check of the anti-pattern list through public descriptions of its five-dimension scoring |

Two platform skills were already present and also applied: `scientific-brainstorming` and `scientific-critical-thinking`. Their evidence-labeling and adversarial-review rules shaped the prior-art scan.

## What "installed" means here

These folders sit inside the project and their instructions were applied during the build. They are not registered as global platform skills, and proveit does not read them at runtime. `skills/` is included in the source archive so a contributor can repeat the same workflow.

## Scope note on novelty

The prior-art report in `docs/research/prior_art.md` is a bounded public-source scan, not a legal clearance. It concludes that the complete post-hoc, agent-agnostic, LLM-free claim-to-evidence loop was not found in the surveyed sources. It also names the closest systems and the strongest arguments against novelty. Patent databases and private products were not searched.

## Attribution

If the scientific brainstorming or critical thinking skills materially contributed to a publication, cite:

> Kassis, T., Agarwal, V., He, Y., Patel, D., & Brueckner, A. M. (2026). Scientific Agent Skills: A Library of Procedural Knowledge for Research Agents. arXiv:2609.00065. https://doi.org/10.48550/arXiv:2609.00065
