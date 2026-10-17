#!/usr/bin/env python3
"""Pure selector regression; never starts a fixture or writes live files."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("context_fixture", Path(__file__).with_name("test-context-storage.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

class BootstrapSelection(unittest.TestCase):
    def test_provider_pair_requires_own_original_chain(self):
        self.assertEqual(fixture.qualification_selection(None,False,False,True,runtime_provider_pair=True),("^TestInitialBootstrapChainWithRealServices$",1))
        for options in ({}, {"initial_bootstrap_chain":True,"owner_provider_auth":True}, {"initial_bootstrap_chain":True,"runtime_object_roundtrip":True}):
            with self.assertRaises(ValueError):
                fixture.qualification_selection(None,False,False,runtime_provider_pair=True,**options)
        flags={"ASSERVAT_INITIAL_RUNTIME_PROVIDER_PAIR":"1","ASSERVAT_INITIAL_RUNTIME_INSTALLED_OWNER":"1","ASSERVAT_INITIAL_RUNTIME_BRIDGE":"1"}
        ordinary=fixture.qualification_environment(flags,Path("fixture"),Path("work"),False,False)
        self.assertFalse(any(k in ordinary for k in flags))
        pair=fixture.qualification_environment(flags,Path("fixture"),Path("work"),False,False,True,runtime_provider_pair=True)
        self.assertEqual(pair["ASSERVAT_INITIAL_RUNTIME_PROVIDER_PAIR"],"1")
        self.assertEqual(pair["ASSERVAT_INITIAL_RUNTIME_BRIDGE"],"1")
        self.assertNotIn("ASSERVAT_INITIAL_RUNTIME_INSTALLED_OWNER",pair)
        legacy=fixture.qualification_environment(flags,Path("fixture"),Path("work"),False,False,True)
        self.assertEqual(legacy["ASSERVAT_INITIAL_RUNTIME_INSTALLED_OWNER"],"1")
        self.assertNotIn("ASSERVAT_INITIAL_RUNTIME_PROVIDER_PAIR",legacy)

    def test_exact_empty_database_selection(self):
        self.assertEqual(fixture.qualification_selection(None, False, False, True), ("^TestInitialBootstrapChainWithRealServices$", 1))
        with patch.object(fixture.subprocess, "run", side_effect=AssertionError("fixture migration attempted")), patch.object(fixture, "run", side_effect=AssertionError("fixture SQL grants attempted")):
            fixture.prepare_fixture_database(Path("unused"), Path("unused"), "unused", "unused", True)
    def test_no_combined_or_arbitrary_selection(self):
        for arguments in [("TestOther",False,False,True),(None,True,False,True),(None,False,True,True),(None,True,True,False)]:
            with self.assertRaises(ValueError):fixture.qualification_selection(*arguments)
    def test_original_selectors_and_stale_flags(self):
        self.assertEqual(fixture.qualification_selection("TestOther",False,False), ("TestOther",2))
        self.assertEqual(fixture.qualification_selection(None,False,True), ("^TestInitialSchemaHandoverWithRealServices$",1))
        flags={k:"1" for k in ("ASSERVAT_INITIAL_HANDOVER_NATIVE","ASSERVAT_INITIAL_SCHEMA_HANDOVER_NATIVE","ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE")}
        current=fixture.qualification_environment(flags,Path("fixture"),Path("work"),False,False,True)
        self.assertEqual({k:current[k] for k in flags if k in current},{"ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE":"1"})
        ordinary=fixture.qualification_environment(flags,Path("fixture"),Path("work"),False,False)
        self.assertFalse(any(k in ordinary for k in flags))

if __name__ == "__main__":unittest.main()
