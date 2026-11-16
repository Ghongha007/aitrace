# aitrace

Look inside an image or video for traces of how it was made.

`aitrace` reads what a file says about itself and reports it in plain words, with the limits of each signal stated next to it:

- **Content Credentials (C2PA):** whether a manifest is embedded, which software wrote it, and whether it declares the media AI-generated or camera-captured.
- **Declared source type:** the IPTC "digital source type" label, an industry standard that AI image and video services can write into the media they generate.
- **Generator settings:** the prompts, seeds and node graphs that Stable Diffusion tools (AUTOMATIC1111, ComfyUI, Fooocus, InvokeAI, NovelAI) leave in the file.
- **Camera and editing metadata:** camera make, model, lens and capture settings; editing or encoding software.

It is a first-pass triage tool. It works offline, needs only Python 3.10 or newer, and uploads nothing.

## What it is not

**It is not a deepfake detector.** It does not look at the picture, and it gives no "probability of AI". Published tests show that pixel-based detectors lose much of their accuracy on real-world media, so this tool reports only what can be read and checked.

Most files you meet in an investigation will return **NO PROVENANCE SIGNALS**, because social platforms and messaging apps strip metadata on upload. That result tells you nothing either way. The tool is most useful on original files: something sent to you directly, downloaded from a source's own site, or pulled from a generator's gallery.

## Example

Illustrative output (file names and sizes are examples):

```
$ aitrace duck.jpg

duck.jpg
  JPEG, 1024x1024, 184,220 bytes

  DECLARED AI-GENERATED
  The file itself says it was made or altered with generative AI. That is the strongest signal a
  file can carry, but it is still a statement inside the file, not a test of the pixels.

  What was found:
   [strong] Stable Diffusion generation settings (prompt, steps, sampler, seed) are stored in the file
       where: EXIF UserComment
       caution: Written by tools such as AUTOMATIC1111 or Forge. EXIF text can be written into any file by hand.
```

## Install

```
git clone https://github.com/Ghongha007/aitrace.git
cd aitrace
pip install .
```

Or run it without installing: `python3 -m aitrace <file>` from inside the folder.

Two sample files are in [`examples/`](examples/) so you can try it straight away:

```
aitrace examples/sample_with_ai_settings.png examples/sample_no_metadata.jpg
```

```
aitrace photo.jpg            report on one file
aitrace *.png -v             several files, plus the metadata that was read
aitrace clip.mp4 --json      machine-readable output
```

## The verdicts

| Verdict | Meaning | What to do next |
|---|---|---|
| **DECLARED AI-GENERATED** | The file carries a label or generator settings saying it was made or altered with generative AI | Strong lead. Record the finding, then look for the original post or gallery page to confirm |
| **DECLARED SYNTHETIC** | The file says it is synthetic or includes synthetic elements, without naming a trained AI model | As above |
| **AI PRODUCT NAMED** | An AI product appears in a software or credit field | The product may have generated the image or only edited it. Find the original |
| **CAMERA ORIGIN CLAIMED, WITH CONTENT CREDENTIALS** | Credentials name a camera or capture app | Verify the signature (see below) |
| **CONTENT CREDENTIALS PRESENT** | A manifest is embedded but says nothing this tool can interpret | Open it in a verifier |
| **CAMERA METADATA PRESENT** | Camera make, model and capture settings are present | Supports a camera origin. Metadata can be copied or forged, and a real photo can still be staged or miscaptioned |
| **EDITING OR ENCODING SOFTWARE NAMED** | The file passed through an editor or encoder | Says nothing about what was changed |
| **WEAK HINTS ONLY** | For example, a default AI output size with no metadata | Not enough to say anything |
| **NO PROVENANCE SIGNALS** | Nothing readable | Normal for anything downloaded from social media. Tells you nothing either way |

Every finding is marked **strong**, **moderate**, **weak** or **info**, with a caution saying what it cannot show.

## What it has been tested on

| Test set | Files | Result |
|---|---|---|
| Real output from AUTOMATIC1111, ComfyUI, Fooocus, InvokeAI and NovelAI (the test images of the open-source [sd-parsers](https://github.com/d3x-at/sd-parsers) project) | 12 | 11 reported as DECLARED AI-GENERATED. The one miss stores its settings invisibly inside the pixels ("stealth" mode), which this tool does not read |
| Real signed images and one signed video from the [C2PA public test files](https://github.com/c2pa-org/public-testfiles) | 6 | Manifests found in all signed files and the signing software read correctly. None wrongly reported as AI |
| Hand-built sample files covering each signal, plus damaged and truncated files | 18 unit tests | All pass |

The first run on real files found one false match (a product name matched by chance inside binary thumbnail data) and three generator formats that were missed. All four are fixed and covered by tests.

## Limits

- **Not tested on real files from OpenAI, Google, Adobe Firefly, Midjourney, Meta or the AI video generators.** The checks for those follow the published C2PA and IPTC specifications and the labels those companies say they write. They have not been confirmed against real downloads.
- **Signatures are not verified.** `aitrace` reports that Content Credentials exist and what they claim. It does not check that they are intact or who signed them. Use [contentcredentials.org/verify](https://contentcredentials.org/verify) or [c2patool](https://github.com/contentauth/c2pa-rs) for that.
- **Invisible watermarks are not checked.** SynthID and similar marks live in the pixels or audio and need the maker's own detector.
- **Every signal here can be removed, and most can be faked.** Stripping metadata is trivial and usually automatic. Adding a false camera tag or a false "AI-generated" label takes one command. Treat the result as a lead to confirm, never as proof.
- **Absence means nothing.** No signal does not mean real, and it does not mean fake.
- **HEIC, AVIF, WebP and video files are scanned more simply** than JPEG and PNG, and have had little or no testing on real files.
- **It cannot tell you that an image is real.** Nothing that reads metadata can.

## Using it in a verification workflow

1. Get the most original copy of the file you can. A screenshot or a re-upload has already lost its metadata.
2. Run `aitrace`. Record the verdict and the findings with the file's hash.
3. If credentials are present, verify them with one of the tools above.
4. Whatever the result, continue with the usual checks: reverse image search for earlier copies, the source's history, location, time, and whether the content fits the claim.
5. When you publish, say what you found and how: "the file's metadata includes Stable Diffusion settings", not "the image is fake".

If the file has GPS data, `aitrace` tells you so but does not print the coordinates. Handle such files with care.

## Tests

```
python3 -m unittest discover -s tests
```

## Related

- [verify-mcp](https://github.com/Ghongha007/verify-mcp): an MCP server with keyless, read-only verification lookups
- [osint-skills](https://github.com/Ghongha007/osint-skills): agent skills for verification, geolocation, chronolocation and fact-checking
- [ai-for-osint](https://github.com/Ghongha007/ai-for-osint): AI tools for investigators, with where each runs and its known limits
- [india-osint](https://github.com/Ghongha007/india-osint): public records and open data for investigating stories in India
- [chat2net](https://github.com/Ghongha007/chat2net): turn a chat or social-media export into a Gephi network

## Licence

MIT. Made by [OSINT JOURNO](https://github.com/OSINT-JOURNO).
