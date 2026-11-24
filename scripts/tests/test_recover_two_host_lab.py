import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "recovery", Path(__file__).resolve().parents[1] / "recover_two_host_lab.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class RecoveryConfigTests(unittest.TestCase):
    def test_memory_controller_is_required_before_launch(self):
        lab.require_memory_controller("cpuset cpu io memory pids\n")
        for controllers in ("cpuset cpu io pids", "", "memory_fake"):
            with self.subTest(controllers=controllers), self.assertRaises(RuntimeError):
                lab.require_memory_controller(controllers)

    def test_each_node_only_dials_other_three(self):
        for i, node in enumerate(lab.NODES):
            args = lab.launch_args(i)
            peers = args[args.index("--bootnodes") + 1].split(",")
            self.assertEqual(len(set(peers)), 3)
            self.assertNotIn(f"/ip4/{node[2]}/tcp/{node[3]}", peers)

    def test_recovery_never_initializes_origin(self):
        for i in range(4):
            args = lab.launch_args(i)
            self.assertIn("--setenv=AINCORE_GUARD_ORIGIN_INIT=0", args)
            self.assertNotIn("--setenv=AINCORE_GUARD_ORIGIN_INIT=1", args)
            self.assertIn(f"{lab.NODES[i][1]}/aincore-lab-20261020/data-{i}", args)

    def test_bounded_lifetime_and_distinct_test_units(self):
        for i in range(4):
            args = lab.launch_args(i)
            self.assertIn("--property=RuntimeMaxSec=30min", args)
            self.assertIn(f"--unit={lab.UNIT_PREFIX}-{i}", args)
            self.assertIn("--property=RemainAfterExit=yes", args)
