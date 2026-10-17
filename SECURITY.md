# Security Policy

## Supported Versions

| Version  | Supported          |
| -------- | ------------------ |
| `1.3.x`  | :white_check_mark: |
| `< 1.3`  | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately via one of the following channels:

- **Email:** [notbadtb2@gmail.com](mailto:notbadtb2@gmail.com)
- **Telegram:** [@Voobrazhenie_20](https://t.me/Voobrazhenie_20)

Please include in your report:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce or a proof-of-concept (PoC), if available.
3. Affected version(s) and component(s) (e.g., `parsers.py`, `engine.py`).
4. Your suggested fix, if any.

## Response Timeline

- **Acknowledgement:** within 48 hours.
- **Initial assessment:** within 7 days.
- **Resolution / mitigation:** as fast as practicable, depending on severity.

## Disclosure Policy

We follow **coordinated disclosure**: the reporter and the maintainer agree on a
public disclosure date (typically within 90 days of the initial report, or sooner
once a fix is released). Credit will be given to the reporter unless anonymity is
requested.

## Scope Notes

- Log Sentinel is a **defensive** (blue-team) tool. Parsing untrusted log files is
  an expected use case — bugs leading to crashes, hangs, or resource exhaustion on
  maliciously crafted input are in scope and appreciated.
