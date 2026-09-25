"""Runtime validation against MCR-A, without a second schema authority."""
from __future__ import annotations

import json
from copy import deepcopy
from functools import lru_cache
from typing import Any, ClassVar
from urllib.parse import urldefrag, urljoin

import yaml
from jsonschema import Draft202012Validator
from pydantic import RootModel, model_validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from app.core.campaign_recycling import ROOT

BASE = 'https://contracts.codestra.co/campaign-recycling/'
API_URI = BASE + 'campaign-engine.openapi.yaml'
API = yaml.safe_load((ROOT / 'contracts/campaign-recycling/campaign-engine.openapi.yaml').read_text())
DOCUMENTS = {API_URI: API}
for path in (ROOT / 'contracts/campaign-recycling').glob('*.schema.json'):
    document = json.loads(path.read_text())
    DOCUMENTS[document['$id']] = document
REGISTRY = Registry().with_resources(
    (uri, Resource.from_contents(doc, default_specification=DRAFT202012))
    for uri, doc in DOCUMENTS.items()
)


def expand(value: Any, base: str = API_URI) -> Any:
    """Inline local references for FastAPI/OpenAPI; never resolve over the network."""
    if isinstance(value, list):
        return [expand(item, base) for item in value]
    if not isinstance(value, dict):
        return value
    if '$ref' in value:
        uri, pointer = urldefrag(urljoin(base, value['$ref']))
        target = DOCUMENTS[uri]
        for segment in pointer.lstrip('/').split('/') if pointer else []:
            target = target[segment.replace('~1', '/').replace('~0', '~')]
        return {**expand(target, uri), **expand({k:v for k,v in value.items() if k != '$ref'}, base)}
    return {k: expand(v, base) for k,v in value.items() if k not in ('$id', '$schema')}


@lru_cache(maxsize=128)
def validator(ref: str) -> Draft202012Validator:
    return Draft202012Validator(
        {'$ref': urljoin(API_URI, ref)}, registry=REGISTRY,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


class ContractDocument(RootModel[dict[str, Any]]):
    reference: ClassVar[str]

    @model_validator(mode='after')
    def validate_contract(self):
        # Do not put schema errors (which can contain PII) in HTTP responses.
        if not validator(self.reference).is_valid(self.root):
            raise ValueError('document violates the frozen campaign contract')
        return self


class PlanRequest(ContractDocument):
    reference = '#/components/schemas/PlanRequest'


class ExecuteRequest(ContractDocument):
    reference = '#/components/schemas/ExecuteRequest'


class DeliveryEvent(ContractDocument):
    reference = './delivery-event.v1.schema.json'


class SuppressionRequest(ContractDocument):
    reference = './channel-health.v1.schema.json#/$defs/SuppressionRequest'


def operation_contract(path: str, method: str) -> dict:
    return expand(deepcopy(API['paths'][path][method]))
