# CHOKEPOINT

**ChronoForge 2026 (NITK Surathkal), Cybersecurity track. Team Hercules.**

CHOKEPOINT is a defensive attack-path agent for smart-city command centres. It finds the **fewest fixes that cut every route** from an attacker to a city's water, traffic, and other critical services. It treats required service flows as hard constraints and **verifies each plan on a digital twin** before recommending it.

This repository contains the Round 1 proof-of-concept engine. It runs on a **synthetic** twin and never scans or exploits a real system.

```bash
cd prototype/chokepoint
python3 run_demo.py
python3 -m unittest discover -s tests -v
```

See [prototype/chokepoint/README.md](prototype/chokepoint/README.md) for the method and results.
