// SkillSeal CLI — init command
// Scaffolds an empty skill package: SKILL.md template, TRUST.json skeleton, ATTESTATIONS/ dir

import { join } from "node:path";
import { mkdir } from "node:fs/promises";

const SKILL_MD_TEMPLATE = `---
skill: my-skill
version: 0.1.0
author: author@example.com
github: username
author_fingerprint: ""
signed: false
attestations: []
manifest_hash: ""
---

# My Skill

**Description:** A brief description of what this skill does.

## Instructions

1. Step one
2. Step two
3. Step three
`;

const TRUST_JSON_TEMPLATE = {
  schema_version: "0.1.0",
  author: {
    name: "",
    email: "",
    github: "",
    fingerprint: "",
    key_url: "",
  },
  attestations: [],
};

export async function initCommand(skillDir: string): Promise<void> {
  console.log(`Initializing skill package: ${skillDir}`);

  // Create directory if it doesn't exist
  await mkdir(skillDir, { recursive: true });

  // Create SKILL.md
  const skillMdPath = join(skillDir, "SKILL.md");
  const skillMdFile = Bun.file(skillMdPath);
  if (await skillMdFile.exists()) {
    console.log("  SKILL.md already exists, skipping.");
  } else {
    await Bun.write(skillMdPath, SKILL_MD_TEMPLATE);
    console.log("  Created SKILL.md");
  }

  // Create TRUST.json
  const trustPath = join(skillDir, "TRUST.json");
  const trustFile = Bun.file(trustPath);
  if (await trustFile.exists()) {
    console.log("  TRUST.json already exists, skipping.");
  } else {
    await Bun.write(trustPath, JSON.stringify(TRUST_JSON_TEMPLATE, null, 2) + "\n");
    console.log("  Created TRUST.json");
  }

  // Create ATTESTATIONS directory
  const attestDir = join(skillDir, "ATTESTATIONS");
  await mkdir(attestDir, { recursive: true });
  console.log("  Created ATTESTATIONS/");

  console.log("\nSkill package initialized. Next steps:");
  console.log("  1. Edit SKILL.md with your skill instructions");
  console.log("  2. Update the YAML frontmatter (skill name, author, github)");
  console.log("  3. Run: skillseal sign " + skillDir);
}
