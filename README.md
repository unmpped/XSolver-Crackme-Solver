# xsolver 1.9.1

xsolver analyses ELF and PE binaries and tries to find the input that makes them succeed. It can also inspect license checks in ordinary software, not just crackmes, when you own the software or have permission to analyse it. Results depend on the target; finding a valid license is never guaranteed. Analysis runs on your PC; there is no xsolver scan server.

## Run it

### Windows

1. Install WSL2 with Ubuntu. Keep an internet connection for setup.
2. Open `xsolver.exe`. It starts the interface through WSL. First launch installs dependencies and may ask for your Ubuntu password.
3. Choose **Solve** to pick a file in Explorer. Use **Inspect** for static analysis, **Batch** for a folder, or **Settings** to tune limits.
4. Watch candidate strings and progress. If xsolver finds a key, choose **Save JSON** to write a report beside the target. Press `Q` to quit.

Windows `.exe` targets run through Wine inside WSL2.

### Linux

Run `bash setup.sh`, then `bash launch.sh` for the interface. To solve directly:

```bash
bash launch.sh solve /path/to/target --budget 30
```

## About

Choose **About** in the interface for project links and credits.

## A few things to know

- xsolver doesn't upload targets to a remote scan service. First-time setup downloads dependencies from Ubuntu and Python package sources.
- Solving is heuristic. Some targets won't be solved.
- Targets are executed locally with your account. **xsolver is not a sandbox**: an unknown target may access files or the network. Only run binaries you trust and are allowed to analyse.
- PE behaviour under Wine may differ from native Windows.
- Windows may warn that `xsolver.exe` is unsigned.
- This source ZIP has no `LICENSE` yet. Choose one before publishing if you want to grant reuse rights.

## Don't trust it?

Fair. Read the code first: the solver is in [`xsolver/`](./xsolver/), and the Windows launcher source is [`tools/xsolver_launcher.c`](./tools/xsolver_launcher.c). Check what it does before running it.
