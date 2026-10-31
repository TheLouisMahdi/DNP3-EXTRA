# DNP3-EXTRA project rules

- Preserve the OpenDNP3 architecture.
- Reuse existing implementations before extending them.
- Minimize unnecessary changes and never modify unrelated files.
- Keep support for both Master and Outstation.
- Use permanent tests; do not use temporary application main.cpp changes as test harnesses.
- Review Git diffs before staging and stage only relevant, safe files.
- Commit completed, verified changes with descriptive messages and push to origin/develop after every source-changing task.
- Do not push failed changes to main. Preserve failed work locally or on an explicitly labeled WIP branch.
- Never commit secrets, compiled binaries, or unauthorized documents.
- Never force-push or rewrite history.
- Report commit SHA, branch, test results, and push status in the final report.
- Verify the remote branch before reporting a successful push.
- Preserve local commits and report PUSH_FAILED if authentication or networking fails.
- Read-only tasks must not create empty commits.
