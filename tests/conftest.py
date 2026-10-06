"""Test-wide setup: keep GuardLayer's hash key out of the user's home directory."""

import os
import tempfile

os.environ.setdefault("GUARDLAYER_HASH_KEY_FILE", os.path.join(tempfile.mkdtemp(prefix="gl-test-key-"), "hash.key"))
