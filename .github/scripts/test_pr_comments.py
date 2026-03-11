import importlib.util
import pathlib
import unittest
from unittest import mock


SCRIPT_PATH = pathlib.Path(__file__).with_name("pr-comments.py")
SPEC = importlib.util.spec_from_file_location("pr_comments", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
pr_comments = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pr_comments)


class GhGraphQLTests(unittest.TestCase):
    def test_gh_graphql_uses_raw_fields_for_string_variables(self) -> None:
        captured: dict[str, object] = {}

        def fake_run_json(cmd: list[str], *, context: str):
            captured["cmd"] = cmd
            captured["context"] = context
            return {"ok": True}

        with (
            mock.patch.object(pr_comments, "load_graphql", return_value="query Test { viewer { login } }"),
            mock.patch.object(pr_comments, "run_json", side_effect=fake_run_json),
        ):
            result = pr_comments.gh_graphql(
                "resolve_review_thread.graphql",
                threadId="@/tmp/thread-id",
                owner="@octocat",
                repo="certkit",
                number=123,
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(captured["context"], "running GraphQL resolve_review_thread.graphql")
        self.assertEqual(
            captured["cmd"],
            [
                "gh",
                "api",
                "graphql",
                "-f",
                "query=query Test { viewer { login } }",
                "-f",
                "threadId=@/tmp/thread-id",
                "-f",
                "owner=@octocat",
                "-f",
                "repo=certkit",
                "-F",
                "number=123",
            ],
        )


if __name__ == "__main__":
    unittest.main()
