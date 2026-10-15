# Security

## Reporting a problem

Report vulnerabilities privately through GitHub: **Security -> Report a
vulnerability** on this repository. Please do not open a public issue for
anything exploitable. You will get an acknowledgement within 72 hours.

## What drift handles

- **Packet captures contain sensitive data.** drift reads them locally and
  only reports which destinations each device contacted; it never uploads a
  capture or stores payloads.
- **Alerts are opt-in.** `--notify VAR` posts a summary to the webhook URL in
  the named environment variable. The URL is read from the environment, never
  the command line.

## Supply chain

- GitHub Actions are pinned to full commit SHAs.
- Releases publish to PyPI through trusted publishing (OIDC); no long-lived
  token is stored in the repository.
