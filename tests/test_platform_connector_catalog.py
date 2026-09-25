import pytest
from types import SimpleNamespace
from app.platform.connector_catalog import ConnectorCatalogError, describe_connector, list_connectors
from app.platform.adapter import AdapterReadiness

class Registry:
 def describe(self):
  return [{"adapter_id":"a","version":"1","provider_family":"fixture","connector_ids":["c"],
   "capabilities":["CAP"],"command_prefixes":["x."],"supports_readback":True,
   "supports_cancel":False,"supports_status":True,"safe_reexecution":False,"external_effect":False}]
 async def readiness(self,ctx): return {"a":AdapterReadiness(ready=True,detail="ok")}
 policies=SimpleNamespace(capabilities={"CAP":False})

@pytest.fixture
def runtime():
 return SimpleNamespace(registry=Registry(),settings=SimpleNamespace(readiness_timeout_seconds=1,app_env="test",source_sha="sha"),
  dispatch=SimpleNamespace(http=None),safety=SimpleNamespace(classification=lambda c:"synthetic"))

@pytest.mark.asyncio
async def test_catalog_projects_registry_without_enabling_effect(runtime):
 row=await describe_connector(runtime,"c")
 assert row["connector_id"]=="c" and row["health"]=="healthy" and row["enabled"] is False
 assert row["effect_classification"]=={"CAP":"synthetic"}

@pytest.mark.asyncio
async def test_catalog_list_is_deterministic(runtime):
 assert [x["connector_id"] for x in await list_connectors(runtime)]==["c"]

@pytest.mark.asyncio
async def test_unknown_connector_is_normalized(runtime):
 with pytest.raises(ConnectorCatalogError) as exc: await describe_connector(runtime,"missing")
 assert exc.value.code=="connector_unavailable"

def test_required_connector_routes_are_registered_in_source():
 from pathlib import Path
 source=(Path(__file__).resolve().parents[1]/"app/platform/api.py").read_text()
 for route in ('/connectors','/connectors/{connector_id}','/connectors/{connector_id}/capabilities','/connectors/{connector_id}/health','/connectors/{connector_id}/readback','/connectors/{connector_id}/reconcile'):
  assert route in source