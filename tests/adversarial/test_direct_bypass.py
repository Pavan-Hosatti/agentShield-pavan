"""
AgentShield V2 — A1: Direct Bypass Tests

Invariant tested: I1 — No agent or gateway bypass to the protected tool.

Attack: Agent or gateway sends HTTP directly to mock_tool:8002.
Expected: Connection refused / no route; mock tool state unchanged.

Owner: Pavan (design) | Gururaj (integration execution)
"""

from __future__ import annotations
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))


# ---------------------------------------------------------------------------
# Unit-level: Verify network topology is specified
# ---------------------------------------------------------------------------

class TestNetworkTopologySpec:
    """
    Document the required network topology.
    The actual enforcement is at Docker network level (executor_net).
    These tests verify the specification is consistent.
    """

    def test_mock_tool_is_not_on_agent_net(self):
        """
        According to docker-compose.yml, mock_tool is only on executor_net.
        It must not be on agent_net.
        This test documents the requirement; enforcement is in docker-compose.
        """
        # Read docker-compose.yml and verify mock_tool networks
        import yaml
        compose_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'docker-compose.yml'
        )
        if not os.path.exists(compose_path):
            pytest.skip("docker-compose.yml not found")

        with open(compose_path) as f:
            compose = yaml.safe_load(f)

        mock_tool_networks = compose.get("services", {}).get("mock_tool", {}).get("networks", [])
        gateway_networks = compose.get("services", {}).get("gateway", {}).get("networks", [])

        # mock_tool must be ONLY on executor_net
        assert "executor_net" in mock_tool_networks, "mock_tool must be on executor_net"
        assert "agent_net" not in mock_tool_networks, "mock_tool must NOT be on agent_net"
        assert "internal_net" not in mock_tool_networks, "mock_tool must NOT be on internal_net"

    def test_gateway_is_not_on_executor_net(self):
        """Gateway must not be on executor_net — it cannot reach mock_tool."""
        import yaml
        compose_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'docker-compose.yml'
        )
        if not os.path.exists(compose_path):
            pytest.skip("docker-compose.yml not found")

        with open(compose_path) as f:
            compose = yaml.safe_load(f)

        gateway_networks = compose.get("services", {}).get("gateway", {}).get("networks", [])
        assert "executor_net" not in gateway_networks, \
            "SECURITY: gateway must NOT be on executor_net"

    def test_executor_is_on_both_internal_and_executor_nets(self):
        """Executor must be on both internal_net (for Redis/PG/OPA) and executor_net (for mock_tool)."""
        import yaml
        compose_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'docker-compose.yml'
        )
        if not os.path.exists(compose_path):
            pytest.skip("docker-compose.yml not found")

        with open(compose_path) as f:
            compose = yaml.safe_load(f)

        executor_networks = compose.get("services", {}).get("executor", {}).get("networks", [])
        assert "internal_net" in executor_networks, "executor must be on internal_net"
        assert "executor_net" in executor_networks, "executor must be on executor_net"
        assert "agent_net" not in executor_networks, "executor must NOT be on agent_net"


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.adversarial
class TestDirectBypassIntegration:
    """
    A1: Direct access attempt from agent/test context.
    """

    def test_agent_cannot_reach_mock_tool_directly(self, mock_tool_url):
        """
        Attempt a direct HTTP GET to mock_tool.
        From outside docker-compose network, this should be unreachable.
        From inside agent_net (no executor_net), this should also fail.

        Evidence: connection error or 000 status; mock state unchanged.
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker network verification.")

    def test_gateway_cannot_reach_mock_tool(self):
        """
        Verify that the gateway service (on internal_net but not executor_net)
        cannot reach mock_tool:8002.
        """
        pytest.skip("NOT_IMPLEMENTED — requires exec inside docker containers.")

    def test_only_executor_can_reach_mock_tool(self):
        """
        The executor service (on executor_net) can successfully call mock_tool.
        Verify this as the control test.
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker exec verification.")
