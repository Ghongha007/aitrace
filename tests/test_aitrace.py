import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(__file__))
import make_samples as m
from aitrace.core import inspect, parse_exif, _find_names, GENERATORS
from aitrace.cli import main

class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
    def tearDown(self):
        self.d.cleanup()
    def rep(self, name, data):
        p = os.path.join(self.d.name, name)
        with open(p, "wb") as f:
            f.write(data)
        return inspect(p)
    def kinds(self, r):
        return {(f.kind, f.strength) for f in r.findings}

    def test_stable_diffusion_png(self):
        r = self.rep("sd.png", m.png([m.text("parameters", "a cat\nNegative prompt: blurry\nSteps: 30, Sampler: Euler a, CFG scale: 7, Seed: 1, Size: 1024x1024")]))
        self.assertEqual(r.verdict, "DECLARED AI-GENERATED")
        self.assertEqual((r.format, r.width, r.height), ("PNG", 1024, 1024))
    def test_comfyui_and_novelai_and_invoke(self):
        self.assertEqual(self.rep("c.png", m.png([m.text("prompt", '{"3": {"class_type": "KSampler", "inputs": {}}}')])).verdict, "DECLARED AI-GENERATED")
        self.assertEqual(self.rep("n.png", m.png([m.text("Software", "NovelAI"), m.text("Comment", '{"steps": 28, "sampler": "k_euler"}')])).verdict, "DECLARED AI-GENERATED")
        self.assertEqual(self.rep("i.png", m.png([m.itxt("invokeai_metadata", '{"model": "x"}')])).verdict, "DECLARED AI-GENERATED")
    def test_word_prompt_alone_is_not_enough(self):
        r = self.rep("p.png", m.png([m.text("prompt", "please crop this"), m.text("parameters", "none")], w=800, h=601))
        self.assertEqual(r.verdict, "NO PROVENANCE SIGNALS")
    def test_iptc_source_type_in_jpeg(self):
        r = self.rep("a.jpg", m.jpeg([m.xmp(m.AI_TYPE + ' photoshop:Credit="Made with Google AI"')], w=1024, h=1024))
        self.assertEqual(r.verdict, "DECLARED AI-GENERATED")
        self.assertIn(("ai", "moderate"), self.kinds(r))          # the credit line names the product
        self.assertEqual((r.width, r.height), (1024, 1024))
    def test_c2pa_ai(self):
        r = self.rep("c2.jpg", m.jpeg([m.jumbf(b"...claim_generator\x67ChatGPT ... http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia ...")]))
        self.assertEqual(r.verdict, "DECLARED AI-GENERATED")
        self.assertIn(("credentials", "info"), self.kinds(r))
        self.assertTrue(any("does not verify" in f.caveat for f in r.findings))
    def test_c2pa_from_a_camera_is_not_called_ai(self):
        r = self.rep("leica.jpg", m.jpeg([(0xE1, b"Exif\x00\x00" + m.exif("Leica Camera AG", "M11-P", shot=True)),
                                          m.jumbf(b"claim_generator\x6bLeica M11-P digitalsourcetype/digitalCapture")]))
        self.assertEqual(r.verdict, "CAMERA ORIGIN CLAIMED, WITH CONTENT CREDENTIALS")
        self.assertFalse(any(f.kind == "ai" for f in r.findings))
    def test_camera_exif(self):
        r = self.rep("cam.jpg", m.jpeg([(0xE1, b"Exif\x00\x00" + m.exif("SONY", "ILCE-7M4", shot=True))]))
        self.assertEqual(r.verdict, "CAMERA METADATA PRESENT")
        self.assertEqual(r.metadata["exif"]["Make"], "SONY")
        self.assertEqual(r.metadata["exif"]["DateTimeOriginal"], "2026:11:16 10:30:00")
        self.assertEqual(r.metadata["exif"]["ISO"], 200)
        self.assertTrue(any("forged" in f.caveat or "written by hand" in f.caveat for f in r.findings))
    def test_editor(self):
        r = self.rep("ps.jpg", m.jpeg([(0xE1, b"Exif\x00\x00" + m.exif(software="Adobe Photoshop 26.0 (Windows)"))]))
        self.assertEqual(r.verdict, "EDITING OR ENCODING SOFTWARE NAMED")
    def test_generator_named_in_software(self):
        r = self.rep("mj.jpg", m.jpeg([(0xE1, b"Exif\x00\x00" + m.exif(software="Midjourney v7"))]))
        self.assertEqual(r.verdict, "AI PRODUCT NAMED")
    def test_names_inside_binary_manifest_data_are_ignored(self):
        r = self.rep("thumb.jpg", m.jpeg([m.jumbf(b"claim_generator\x77make_test_images/0.16.1" + b"\x00\xff" * 200 + b" +Veo/ Sora Grok " + b"\x01" * 50)]))
        self.assertEqual(r.verdict, "CONTENT CREDENTIALS PRESENT")
        self.assertIn("make_test_images", r.findings[0].what)
    def test_a1111_jpeg_and_fooocus_and_dream(self):
        uc = b"UNICODE\x00" + "photo of a duck\nSteps: 15, Sampler: Euler, CFG scale: 7, Seed: 5".encode("utf-16-be")
        tiff = b"II*\x00\x08\x00\x00\x00\x01\x00" + b"\x69\x87\x04\x00\x01\x00\x00\x00\x1a\x00\x00\x00" + b"\x00\x00\x00\x00"
        import struct
        tiff += struct.pack("<H", 1) + struct.pack("<HHII", 0x9286, 7, len(uc), 26 + 2 + 12 + 4) + b"\x00\x00\x00\x00" + uc
        self.assertEqual(self.rep("a.jpg", m.jpeg([(0xE1, b"Exif\x00\x00" + tiff)])).verdict, "DECLARED AI-GENERATED")
        self.assertEqual(self.rep("f.png", m.png([m.text("parameters", '{"prompt": "x", "base_model": "juggernaut"}'), m.text("fooocus_scheme", "fooocus")])).verdict, "DECLARED AI-GENERATED")
        self.assertEqual(self.rep("d.png", m.png([m.text("Dream", '"a castle" -s 50 -S 123 -W 512 -H 512 -C 7.5')])).verdict, "DECLARED AI-GENERATED")
    def test_web_page_saved_as_image(self):
        r = self.rep("page.jpg", b"<!DOCTYPE html>\n<html><body>Too many requests</body></html>")
        self.assertEqual(r.verdict, "NOT AN IMAGE OR VIDEO")
    def test_stripped_file(self):
        r = self.rep("s.jpg", m.jpeg([], w=1080, h=1350))
        self.assertEqual(r.verdict, "NO PROVENANCE SIGNALS")
        self.assertIn("nothing either way", r.summary)
    def test_size_is_only_a_weak_hint(self):
        r = self.rep("sq.png", m.png([]))
        self.assertEqual(r.verdict, "WEAK HINTS ONLY")
    def test_names_match_whole_words_only(self):
        self.assertEqual(_find_names("Veolia water report, a soraya photo, influx", GENERATORS), [])
        self.assertEqual(_find_names("Made with Adobe Firefly", GENERATORS), ["Adobe Firefly"])
    def test_video_scan(self):
        mp4 = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 12 + b"....\xa9too\x00\x00\x00\x15data\x00\x00\x00\x01\x00\x00\x00\x00Lavf60.16.100" + b"\x00" * 50
        r = self.rep("v.mp4", mp4)
        self.assertEqual(r.format, "MP4")
        self.assertEqual(r.verdict, "EDITING OR ENCODING SOFTWARE NAMED")
        ai = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 12 + b"uuid....jumb....c2pa....claim_generator\x6fSora OpenAI/1.0 digitalsourcetype/trainedAlgorithmicMedia" + b"\x00" * 50
        self.assertEqual(self.rep("ai.mp4", ai).verdict, "DECLARED AI-GENERATED")
    def test_damaged_files_do_not_crash(self):
        good = m.jpeg([(0xE1, b"Exif\x00\x00" + m.exif("SONY", "ILCE-7M4", shot=True))])
        for n in (3, 10, 25, 40, 70, len(good) - 5):
            self.rep(f"t{n}.jpg", good[:n])
        self.rep("bad.png", b"\x89PNG\r\n\x1a\n" + b"\xff" * 40)
        self.rep("empty.bin", b"")
        self.assertEqual(parse_exif(b"II*\x00\xff\xff\xff\xff"), {})
    def test_cli(self):
        p = os.path.join(self.d.name, "sd.png")
        with open(p, "wb") as f:
            f.write(m.png([m.text("parameters", "x\nSteps: 20, Sampler: DPM")]))
        self.assertEqual(main([p]), 0)
        self.assertEqual(main([p, os.path.join(self.d.name, "missing.jpg")]), 2)

if __name__ == "__main__":
    unittest.main()
