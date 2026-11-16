# Sample files

Two small files to try `aitrace` on. Both pictures were drawn by a short script; neither is a photograph or the output of an AI model.

- `sample_with_ai_settings.png` carries a text block in the format that Stable Diffusion tools write (prompt, steps, sampler, seed). It was added by hand to show what `aitrace` reports when it finds one.
- `sample_no_metadata.jpg` has no metadata at all, like most images downloaded from social media.

```
aitrace examples/sample_with_ai_settings.png examples/sample_no_metadata.jpg
```
