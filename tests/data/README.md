# Test data

`corpus.json`: 64 commands (22 attacks, 42 benign) used by `tests/test_corpus.py` against a real tirith.
Reconstructed for the tirith agent-workload work from the tirith README classes, the Hermes test suite,
issues sheeki03/tirith#255-#272 and filler rows; each row records its `provenance`. Copied unchanged
(sha256 `7acda8542a8f835e5939a33ed5223893aed9d596d14425489a4fb0762848235a`). The attack rows are inert
strings for a scanner: nothing in this repository runs them.
