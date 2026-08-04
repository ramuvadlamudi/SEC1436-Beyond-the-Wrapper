# Publish with the GitHub Web UI from macOS

The publication kit contains:

- `repository/` — the exact clean repository contents, including hidden files;
- `release-assets/` — checksum-verified source and runtime archives for a GitHub Release;
- `UPLOAD_TO_GITHUB_FROM_MAC.txt` — a short offline copy of these steps.

## 1. Extract and reveal hidden files

1. Download and extract the publication kit on the Mac.
2. Open the `repository` folder in Finder.
3. Press **Command + Shift + .** to display hidden files.
4. Confirm these items are visible:
   - `.github/`
   - `.env.example`
   - `.gitignore`
   - `.gitattributes`
   - `.editorconfig`

Do not create or upload `.env`.

## 2. Create the repository

Create a new empty GitHub repository. Do not ask GitHub to add a README, licence or `.gitignore`; the approved versions are already in the package.

Suggested description:

> SEC1436 reference patterns for connecting local Ollama models to Splunk: AI Toolkit inference, the evidence-first ARIA agentic copilot, and a DSDL/private-RAG roadmap.

Suggested topics:

```text
splunk secops soc ai-agents ollama air-gapped-llm ai-toolkit dsdl rag incident-response
```

## 3. Upload the files

1. In the empty repository choose **Add file > Upload files**.
2. Open the local `repository` folder.
3. Select the folder's contents, including all hidden items.
4. Drag the selected contents into GitHub.

Upload the contents rather than the outer `repository` folder. `README.md` must appear at the GitHub repository root.

Before committing, confirm the upload list contains at least:

```text
.github/workflows/validate.yml
.env.example
.gitignore
README.md
aria/
docs/
patterns/
product/
scripts/
```

Use a commit message such as `Publish SEC1436 patterns and ARIA v3.0.0-rc11`.

## 4. Validate after upload

1. Open the **Actions** tab.
2. Open **Validate ARIA RC11**.
3. Require the workflow to pass before creating a release.
4. Inspect the repository file tree and confirm `.env`, runtime `data/`, caches and nested release archives are absent.

## 5. Configure repository controls

- Enable branch protection for `main` and require the validation workflow.
- Enable secret scanning, push protection and dependency alerts where available.
- Enable private vulnerability reporting.
- Add approved maintainers.
- Replace `OWNER/REPOSITORY` in `.github/ISSUE_TEMPLATE/config.yml`.
- Complete `PUBLIC_RELEASE_CHECKLIST.md` before changing visibility to public.

## 6. Create the RC11 release

1. Choose **Releases > Draft a new release**.
2. Create tag `v3.0.0-rc11` from the exact validated commit.
3. Mark it as a pre-release.
4. Attach the files in `release-assets/`.
5. Verify each archive against the adjacent `.sha256` file before upload.

Pattern B remains the implemented controlled-preview release. Pattern A is demonstration guidance, and Pattern C is an experimental roadmap rather than a production support commitment.

## Browser fallback for hidden paths

If drag-and-drop does not preserve a hidden directory, choose **Add file > Create new file** and enter the complete path, for example:

```text
.github/workflows/validate.yml
```

GitHub creates the intermediate hidden directories from the path.
