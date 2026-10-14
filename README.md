# PsycoSupport: Information Security Assignment 1

A reproducible, ethical lab workflow and analysis utility for the Fall 2026 Information Security assignment. It is designed for the instructor-provided PsycoSupport Linux binaries and synthetic lab traffic only.

## Important scope

- Upstream lab: [maadilrehman/PsycoSupport](https://github.com/maadilrehman/PsycoSupport). This project does not redistribute its client or server binaries.
- Use synthetic usernames, moods, and concerns. Do not capture or publish real personal conversations.
- Keep the client and server on your Kali VM and capture only the VM's loopback interface (`lo`).
- Assignment 1 asks for captures in both directions. The revised Assignment 2 document describes a different Python/Ollama app and is outside this project.

## Kali setup and capture

1. In Kali, download or clone the upstream PsycoSupport repository and read its README. The repository currently provides `client` and `server` Linux executables at its root.
2. In a Kali terminal, from the downloaded repository directory, make the supplied programs executable:

   ```bash
   chmod +x client server
   ```

3. Start the server in one terminal:

   ```bash
   ./server
   ```

4. Start Wireshark in Kali, select the loopback interface (`lo`), begin capture, and use synthetic cases in the client. If the port is known, use a display filter such as `tcp.port == 5000`; otherwise inspect the server's listening socket and use the observed port.
5. For each session, use **Follow → TCP Stream** to record the exact application ciphertext sent client-to-server and server-to-client. Label direction, mood, and a non-identifying test case ID. Repeat until you have at least five ciphertexts total, including at least one in each direction (the rubric encourages 3–5 decryptions).
6. Save screenshots or a `.pcapng` as evidence. Do not include real personal data. Store captures privately; this repository ignores local capture/result files by default.
7. Copy only the ciphertext strings and synthetic metadata into `data/ciphertexts.csv` using `data/ciphertexts_template.csv` as a guide.

The VM is the recommended environment because both supplied programs are Linux executables and Wireshark can capture the VM's own loopback traffic. Keep the lab isolated; do not bridge or sniff unrelated networks.

## Run the analysis

Python 3.10+ standard library only:

```bash
python3 scripts/analyze_affine.py --input data/ciphertexts.csv --output results
```

The utility creates:

- `results/frequencies.csv`: letter counts, percentages, and English reference percentages for each sample.
- `results/frequency_*.svg`: captured-versus-English frequency charts grouped by direction and mood.
- `results/key_candidates.csv`: top affine key hypotheses for each direction/mood group.
- `results/analysis_notes.md`: sample sizes and interpretation reminder.

The candidate ranking is a starting point, not proof. For short ciphertexts or text without normal word spacing, frequency statistics may be misleading. Compare several captures in the same direction/mood group, confirm that one key decrypts each relevant sample, and justify the winning key with your observed plaintext patterns and algebra.

## Affine cipher reference

Map `A=0, B=1, ..., Z=25`. Encryption is

\[
E(x) = (a x + b) \bmod 26,
\]

where `gcd(a, 26) = 1`. Decryption is

\[
D(y) = a^{-1}(y-b) \bmod 26.
\]

If a likely plaintext/ciphertext letter pair is `x₁ → y₁` and another is `x₂ → y₂`, then

\[
a = (y₂-y₁)(x₂-x₁)^{-1} \bmod 26, \qquad b = y₁-a x₁ \bmod 26.
\]

The modular inverse exists only when `gcd(x₂-x₁, 26) = 1`. If not, choose a different pair. Verify `gcd(a,26)=1`, compute `a⁻¹`, and check the recovered key against all samples to which that key is meant to apply. Since direction, username, or mood may affect the implementation, do not assume one global key until the evidence supports it.

## Repository contents

- `scripts/analyze_affine.py` — frequency reports, SVG charts, and candidate search.
- `data/ciphertexts_template.csv` — capture schema.
- `report/report_template.md` — structured report scaffold.
- `evidence/`, `results/` — local outputs are ignored; add only sanitized, intentionally shareable evidence.

## Attribution

The PsycoSupport binaries and lab application belong to the upstream project. This repository contains independent analysis materials for the assignment and links to the upstream source. Follow your course instructions and any license/attribution requirements from the instructor.
