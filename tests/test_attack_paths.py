import unittest

from src.graph import find_paths, validate_graph
from src.models import Edge, Node
from src.scoring import score_path


class AttackPathTests(unittest.TestCase):
    def setUp(self):
        self.nodes = {
            "entry": Node("entry", "Entry", "resource", "aws", 3, internet_exposed=True),
            "role": Node("role", "Role", "role", "aws", 3),
            "target": Node("target", "Target", "secret", "aws", 5, privileged=True),
        }
        self.edges = [
            Edge("entry", "role", "assumes", 4, 2),
            Edge("role", "target", "reads", 4, 1),
        ]

    def test_finds_path_to_protected_target(self):
        paths = find_paths(self.nodes, self.edges, {"entry"}, {"target"})
        self.assertEqual(1, len(paths))
        self.assertEqual(("entry", "role", "target"), paths[0].nodes)

    def test_path_score_is_bounded(self):
        result = score_path(self.nodes, ("entry", "role", "target"), tuple(self.edges))
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 100)

    def test_internet_exposure_increases_score(self):
        exposed = score_path(self.nodes, ("entry", "role", "target"), tuple(self.edges)).score
        internal_nodes = dict(self.nodes)
        internal_nodes["entry"] = Node("entry", "Entry", "resource", "aws", 3, internet_exposed=False)
        internal = score_path(internal_nodes, ("entry", "role", "target"), tuple(self.edges)).score
        self.assertGreater(exposed, internal)

    def test_weak_controls_increase_score(self):
        weak = score_path(self.nodes, ("entry", "role", "target"), tuple(self.edges)).score
        strong_edges = (Edge("entry", "role", "assumes", 4, 5), Edge("role", "target", "reads", 4, 5))
        strong = score_path(self.nodes, ("entry", "role", "target"), strong_edges).score
        self.assertGreater(weak, strong)

    def test_cycles_are_not_followed_forever(self):
        cyclic = self.edges + [Edge("role", "entry", "returns", 2, 3)]
        paths = find_paths(self.nodes, cyclic, {"entry"}, {"target"}, max_hops=5)
        self.assertEqual(1, len(paths))

    def test_unknown_edge_node_fails_closed(self):
        with self.assertRaises(ValueError):
            validate_graph(self.nodes, [Edge("entry", "missing", "bad")])

    def test_duplicate_edge_fails_closed(self):
        edge = Edge("entry", "role", "assumes")
        with self.assertRaises(ValueError):
            validate_graph(self.nodes, [edge, edge])

    def test_invalid_criticality_is_rejected(self):
        with self.assertRaises(ValueError):
            Node("bad", "Bad", "resource", "aws", criticality=6)


if __name__ == "__main__":
    unittest.main()
