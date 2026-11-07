import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P11ToolchainTests(unittest.TestCase):
    def test_linux_ndk_tool_resolution(self):
        build = load("p11_build", ROOT / "tools/build_renoace_p11_probe.py")
        setup = load("p11_setup_for_tool", ROOT / "tools/setup_renoace_ndk.py")
        tool_dir = setup.DEFAULT_ROOT / setup.TOOL_RELATIVE
        if not (tool_dir / "clang").is_file():
            self.skipTest("pinned Linux NDK is not installed")
        self.assertEqual(build.tool(tool_dir, "clang"), tool_dir / "clang")
        self.assertEqual(build.tool(tool_dir, "ld.lld"), tool_dir / "ld.lld")

    def test_pinned_ndk_setup_metadata(self):
        setup = load("p11_setup", ROOT / "tools/setup_renoace_ndk.py")
        self.assertEqual(setup.VERSION, "30.0.14904198")
        self.assertEqual(setup.SHA1, "26b746e5a1e7ac3371f2a862a2f52a7c0740aa8a")
        self.assertIn("llvm-objdump", setup.TOOLS)


if __name__ == "__main__":
    unittest.main()
