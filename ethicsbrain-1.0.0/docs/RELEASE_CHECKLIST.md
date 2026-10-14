# Release validation checklist

Run from the repository root:

```powershell
python -m unittest discover -s tests -v
python -m ethicsbrain.benchmark --out-dir reports/benchmark
python -m ethicsbrain.retrieval_benchmark --out-dir reports/retrieval
python -m ethicsbrain.policy_cli validate configs/policy.example.json
python -m pip wheel --no-deps --no-build-isolation . --wheel-dir dist
```

Optional semantic NLI evaluation requires `python -m pip install -e ".[nli]"` and an available/downloaded model checkpoint.

Review before publishing:

- [ ] No `.env`, provider keys, real prompts, audit logs, personal data, or private customer datasets.
- [ ] Version and changelog match the release tag.
- [ ] Unit and integration tests run on supported Python versions.
- [ ] Benchmark reports state dataset size and synthetic/representativeness limits.
- [ ] Wheel installs in a clean environment and default datasets are packaged.
- [ ] Archive and wheel SHA-256 files verify.
- [ ] Documentation does not claim universal control or zero hallucinations.
- [ ] Security limitations and trust boundaries are disclosed.
