# DeepSeek Harness locator

Cross-platform, read-only installation discovery for Windows, macOS, and Linux.

```sh
node tools/deepseek-harness-locator.mjs --json
node tools/deepseek-harness-locator.mjs --first
```

Set `DEEPSEEK_HARNESS_PATH` when a custom installation directory should be checked first.


## Windows CMD

Run the included script directly from `cmd.exe`:

```bat
tools\find-deepseek-harness.cmd
```

It prints the installation directory and returns exit code 0 when found, 1 otherwise. Set `DEEPSEEK_HARNESS_PATH` to check a custom location first.
