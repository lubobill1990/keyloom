# Keyloom branding

The original K mark and README lockup were generated with the user-requested `gpt-image-2-5-sunburst` (GPT Image 2.5) on 2026-11-17. Only the public Keyloom branding brief and the generated mark reference were supplied; no vault data, source code, credentials or private screenshots were sent.

- `icon-source.png`, `banner-source.png`: original model outputs, retained with their provenance metadata.
- `logo.png`: standalone lockup derived from the generated banner.
- `icon.png`: application/favicon mark with padding normalized for small sizes.
- `icon.ico`: Windows 16/24/32/48/64/128/256px representations.
- `readme-banner.png`: a shallow, uncropped-content README presentation.

Rebuild derivatives with `uv run --project backend --group build python scripts/brand-assets.py`; validate with `--check`. CI consumes committed assets and never calls an image API.

Branding is offered with the project under MIT to the extent rights are held. No trademark clearance or exclusive rights in AI-generated artwork are claimed.
