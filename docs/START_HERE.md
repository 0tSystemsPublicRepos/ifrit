# IFRIT Proxy - START HERE

Welcome! This file will guide you through the complete IFRIT Proxy documentation package.

## Quick Navigation by Role

### I'm a Manager/Executive
Read: docs/ifrit_executive_summary.md (5-10 minutes)

### I'm a Security Team Lead
Read: docs/ifrit_documentation.md (15-20 minutes)

### I'm a Developer/Contributor
Read: docs/ifrit_architecture.md (30-40 minutes)

## Key Concepts (2-Minute Summary)

IFRIT Proxy is an intelligent reverse proxy that sits between attackers and your real infrastructure.

When an attack comes in, IFRIT makes a smart decision: Is this obviously malicious? Is it a pattern we've seen before? Or do we need to ask Claude/GPT?

If it's an attack, IFRIT serves fake data back to the attacker (fake credentials, fake database records, etc.). This tricks the attacker while revealing their tools and techniques.

IFRIT learns continuously. Each attack analyzed becomes a learned pattern. After one week, 80% of attacks are caught instantly from the local database without external API calls.

## Next Steps

1. Read the main documentation in docs/
2. Review the architecture diagrams
3. Deploy locally with Docker
4. Start contributing code

---

Generated: November 2, 2024
Project: IFRIT Proxy
Status: MVP Development (v0.1)
