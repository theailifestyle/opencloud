"""Test-only: push an invalid route straight into the agent's renderer to prove validate+rollback."""
import sys
sys.path.insert(0, "/opt/agent")
import agent
app = agent.load(sys.argv[1])
app["route"] = dict(agent.route_cfg(app), health_path="/health", health_interval="not-a-duration")
try:
    agent.route(app)
    print("applied")
except agent.Bad as err:
    print("rolled back:", str(err)[:120])
