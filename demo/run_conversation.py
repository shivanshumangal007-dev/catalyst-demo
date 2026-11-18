"""Scripted conversation demo for the VulnReach PR chat agent.

Shows the agent debating three verdicts (reachable, not_reachable, uncertain)
and changing its answer after the user supplies new information.

Run:

    python demo/run_conversation.py
"""

from __future__ import annotations

from vulnreach.agent.pr_chat import PRChatAgent, RuleBasedLLMClient, build_pr_comment
from demo.pr_scenario import build_scenario


def _print_header(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main() -> None:
    scenario = build_scenario()

    # ------------------------------------------------------------------ 1. reachable verdict
    _print_header("VERDICT 1: reachable (lib@1.0.0, DEMO-REACHABLE-1)")
    ctx = scenario["reachable"]
    agent = PRChatAgent(
        verdict=ctx["verdict"],
        analyzer=ctx["analyzer"],
        project_path=ctx["project_path"],
        alert=ctx["alert"],
        vulnerable_functions=ctx["vulnerable_functions"],
        fix_commit=ctx["fix_commit"],
        call_graph=ctx["call_graph"],
        llm_client=RuleBasedLLMClient,
    )
    print(build_pr_comment(agent.verdict))
    print("\n--- Conversation ---")
    print("User: Is lib.vulnerable_function actually reachable?")
    print(agent.respond("Is lib.vulnerable_function actually reachable?"))
    print("\nUser: Can you show me the exact call path?")
    print(agent.respond("Can you show me the exact call path?"))

    # ------------------------------------------------------------------ 2. not_reachable verdict
    _print_header("VERDICT 2: not_reachable (lib@1.0.0, DEMO-SAFE-1)")
    ctx = scenario["not_reachable"]
    agent2 = PRChatAgent(
        verdict=ctx["verdict"],
        analyzer=ctx["analyzer"],
        project_path=ctx["project_path"],
        alert=ctx["alert"],
        vulnerable_functions=ctx["vulnerable_functions"],
        fix_commit=ctx["fix_commit"],
        call_graph=ctx["call_graph"],
        llm_client=RuleBasedLLMClient,
    )
    print(build_pr_comment(agent2.verdict))
    print("\n--- Conversation ---")
    print("User: I think lib.vulnerable_function might be reachable — check again.")
    print(agent2.respond("I think lib.vulnerable_function might be reachable — check again."))
    print("\nUser: What about lib.safe_function — could that lead to the vuln?")
    print(agent2.respond("What about lib.safe_function — could that lead to the vuln?"))

    # ------------------------------------------------------------------ 3. uncertain verdict
    _print_header("VERDICT 3: uncertain (lib@1.0.0, DEMO-DYNAMIC-1)")
    ctx = scenario["uncertain"]
    agent3 = PRChatAgent(
        verdict=ctx["verdict"],
        analyzer=ctx["analyzer"],
        project_path=ctx["project_path"],
        alert=ctx["alert"],
        vulnerable_functions=ctx["vulnerable_functions"],
        fix_commit=ctx["fix_commit"],
        call_graph=ctx["call_graph"],
        llm_client=RuleBasedLLMClient,
    )
    print(build_pr_comment(agent3.verdict))
    print("\n--- Conversation ---")
    print("User: Is lib.vulnerable_function reachable?")
    print(agent3.respond("Is lib.vulnerable_function reachable?"))
    print("\nUser: That getattr only ever receives 'safe_load' from config.")
    print(agent3.respond("That getattr only ever receives 'safe_load' from config."))
    print("\nUser: OK, assuming that's true, is it still uncertain?")
    print(agent3.respond("OK, assuming that's true, is it still uncertain?"))


if __name__ == "__main__":
    main()
