# EthicsBrain v1.0.0 — validation record

Local validation performed for this source snapshot.

| Check | Result | Scope / caveat |
|---|---|---|
| Unit + integration tests | 71 passed | Python 3.13.5 in the authoring environment |
| Safety regression benchmark | 10/10 synthetic cases matched expected outcome | Small synthetic suite; not representative of real-world risks |
| False accepts / false blocks | 0 / 0 | Only within those ten synthetic cases |
| Retrieval benchmark | 8 synthetic queries; hit rate@3 1.00; recall@3 1.00; precision@3 0.4583; MRR 1.00 | Small synthetic dataset; these scores do not establish production retrieval quality |
| Policy CLI | Passed | Sample JSON policy loads and validates |
| Source wheel build | Passed | `ethicsbrain-1.0.0-py3-none-any.whl` built with no runtime dependencies |
| Clean wheel installation | Passed | Tested in a separate local virtual environment, Python 3.13.5 |
| Installed-wheel benchmark smoke | Passed | Safety benchmark reported 0 failed cases; retrieval benchmark ran from packaged default data |
| Gateway HTTP integration | Passed in unit suite | Uses a simulated upstream endpoint; no live hosted provider was tested |
| Optional NLI checkpoint | Not run live | The NLI tests use mocked scores; installing `.[nli]` and downloading the configured checkpoint is required for semantic model evaluation |
| Python 3.10–3.12 matrix | Not run in this environment | CI workflow is configured for those versions; this local environment used Python 3.13.5 |

The validation is an engineering smoke/regression record, not a security certification, independent audit, or proof of zero hallucinations.
