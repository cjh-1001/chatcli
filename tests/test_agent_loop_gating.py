from types import SimpleNamespace
import unittest

from chatcli.agent import Agent
from chatcli.providers.base import LLMResponse


class _NoopTools:
    def to_schemas(self):
        return []


def _make_loop_agent(responses):
    agent = Agent.__new__(Agent)
    agent.config = SimpleNamespace(
        max_tool_rounds=5,
        min_tool_rounds=5,
        auto_compress=False,
        self_correction=True,
    )
    agent.tools = _NoopTools()
    agent.debug = False
    agent._history = []
    agent._current_turn_requires_evidence = False

    calls = {"count": 0}

    def retry_chat(_tool_schemas):
        idx = min(calls["count"], len(responses) - 1)
        calls["count"] += 1
        return responses[idx]

    agent._retry_chat = retry_chat
    agent._prepare_ida_mcp_tools = lambda: None
    agent._flush_text_buffer = lambda: None
    agent._show_usage = lambda _response, _elapsed: None
    agent._safe_print = lambda *args, **kwargs: None
    agent._auto_save = lambda: None
    agent._maybe_compress = lambda: None
    return agent, calls


class AgentLoopGatingTests(unittest.TestCase):
    def test_plain_chat_does_not_force_min_tool_rounds(self):
        agent, calls = _make_loop_agent([
            LLMResponse(text="你好，有什么可以帮你？", tool_calls=[]),
        ])
        agent._current_turn_requires_evidence = agent._requires_evidence_intensive_work("你好")

        text, exhausted = agent._run_tool_loop()

        self.assertFalse(exhausted)
        self.assertEqual(text, "你好，有什么可以帮你？")
        self.assertEqual(calls["count"], 1)
        self.assertFalse(
            any("Exploration required" in str(item.get("content", "")) for item in agent._history)
        )

    def test_evidence_task_still_uses_min_tool_guard(self):
        agent, calls = _make_loop_agent([
            LLMResponse(text="结论：恶意", tool_calls=[]),
            LLMResponse(text="TASK COMPLETE\n结论：恶意", tool_calls=[]),
        ])
        agent._current_turn_requires_evidence = agent._requires_evidence_intensive_work(
            "分析 C:\\samples\\demo.exe"
        )

        text, exhausted = agent._run_tool_loop()

        self.assertFalse(exhausted)
        self.assertEqual(text, "TASK COMPLETE\n结论：恶意")
        self.assertEqual(calls["count"], 2)
        self.assertTrue(
            any("Exploration required" in str(item.get("content", "")) for item in agent._history)
        )

    def test_self_correction_shallow_answer_is_gated_by_task_type(self):
        agent, _calls = _make_loop_agent([])

        self.assertFalse(
            agent._should_self_correct(
                "我需要更多信息才能回答。",
                exhausted=False,
                correction_round=0,
                tools_used=0,
                original_task="随便聊聊",
            )
        )
        self.assertTrue(
            agent._should_self_correct(
                "结论：恶意",
                exhausted=False,
                correction_round=0,
                tools_used=0,
                original_task="分析 C:\\samples\\demo.exe",
            )
        )


if __name__ == "__main__":
    unittest.main()
