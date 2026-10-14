# Affine Cipher Traffic Analysis

A small Python toolkit for exploring classical cryptanalysis through frequency analysis of text encrypted with an affine substitution cipher.

## Overview

The analysis utilities summarize letter frequencies, compare ciphertext distributions with English-language reference frequencies, and rank affine-key candidates for further verification. The repository also includes a structured CSV schema and a report outline.

## Project contents

- `scripts/analyze_affine.py` — frequency summaries, comparison charts, and candidate-key ranking.
- `data/ciphertexts_template.csv` — schema for organizing anonymized sample text.
- `report/report_template.md` — outline for documenting analysis and findings.

## Scope and attribution

This is an educational cryptanalysis project intended for synthetic or otherwise authorized sample text. It is not a secure messaging application. The PsycoSupport demonstration application and its binaries belong to the [upstream project](https://github.com/maadilrehman/PsycoSupport); they are not included in this repository.
