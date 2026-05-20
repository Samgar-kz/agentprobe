import sys
sys.path.insert(0, "examples")
from tool_agent import ToolAgent
from agentprobe.injection.benign_tasks import BENIGN_TASKS
from agentprobe.injection.defenses import ALL_DEFENSES

# берём forward_to_manager (тот что 0%) и защиту none
task = next(t for t in BENIGN_TASKS if t.name == "forward_to_manager")
none_defense = next(d for d in ALL_DEFENSES if d.name == "none")

agent = ToolAgent(
    email_content=task.email_content,
    defense_apply=none_defense.apply,
    backend="openai",
    temperature=0.0,
)
resp = agent.send(task.user_request)

print("=== USER REQUEST ===")
print(task.user_request)
print("\n=== AGENT TEXT RESPONSE ===")
print(resp.text)
print("\n=== TOOL CALLS ===")
for tc in resp.tool_calls:
    print(tc)
print("\n=== VERIFY RESULT ===")
print("expect_forward_to:", task.expect_forward_to)
print("verify passed:", task.verify(resp.text, resp.tool_calls))