# Adaptive Penetration Testing System

This repository contains a modular, event-driven adaptive penetration testing system implemented in Python.

## Project Structure

- `adaptive_pen_test/`
  - `engine.py` - core event engine and state manager
  - `event_state.py` - event and finite state machine definitions
  - `config_loader.py` - YAML loading and template rendering
  - `ai_strategy.py` - rule-based AI decision engine
  - `plugin_manager.py` - plugin registration and execution
  - `defense_sensor.py` - defense detection helpers
  - `forensics.py` - evidence logging and cleanup support
  - `plugins/` - sample attack plugins
  - `configs/level1.1.yaml` - example attack chain
- `ai_rules.yaml` - AI decision rules
- `main.py` - entrypoint for running the engine
- `requirements.txt` - Python dependencies

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py --config adaptive_pen_test/configs/level1.1.yaml --target-ip 192.168.1.100 --attacker-ip 10.0.0.1
```

## Notes

- The engine uses `asyncio` to manage an event queue and plugin execution.
- Attack chain configuration supports variable templates like `{{target.ip}}`.
- Plugins are implemented using a shared `BasePlugin` interface.
- AI strategy is rule-based and can optionally be extended for local LLMs.

## Disclaimer

This code is intended for educational and defensive research purposes only. Use it responsibly and only in authorized environments.
