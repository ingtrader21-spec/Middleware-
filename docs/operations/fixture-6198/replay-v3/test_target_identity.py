import copy
import json
import socket
import urllib.error
from email.message import Message

import pytest

import target_identity as identity


def container():
    return {
        "Id": "a" * 64,
        "Name": "/" + identity.EXPECTED_CONTAINER,
        "Image": identity.EXPECTED_IMAGE_ID,
        "State": {"Running": True, "Status": "running", "Health": {"Status": "healthy"}},
        "Config": {
            "Image": identity.EXPECTED_IMAGE,
            "Labels": {
                "com.docker.compose.project": identity.EXPECTED_PROJECT,
                "com.docker.compose.service": identity.EXPECTED_SERVICE,
                "com.docker.compose.oneoff": "False",
                "com.docker.compose.image": identity.EXPECTED_IMAGE_ID,
            },
        },
        "NetworkSettings": {
            "Networks": {identity.EXPECTED_NETWORK: {"IPAddress": "172.18.0.15"}}
        },
    }


def runner(value=None, candidates=None, internal=True):
    info = value or container()
    ids = candidates if candidates is not None else [info["Id"]]

    def run(args):
        if args[0] == "ps":
            return "\n".join(ids) + ("\n" if ids else "")
        if args[:2] == ["network", "inspect"]:
            return json.dumps([{"Internal": internal}])
        if args[0] == "inspect":
            return json.dumps([info])
        raise AssertionError(args)
    return run


class Response:
    def __init__(self, body, status=200, content_type="application/json"):
        self.status = status
        self.body = json.dumps(body).encode()
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit):
        return self.body


def opener(health=None, ready=None, calls=None):
    health = identity.HEALTH_BODY if health is None else health
    ready = identity.READY_BODY if ready is None else ready

    def open_request(request, timeout):
        assert timeout == 5
        if calls is not None:
            calls.append((request.full_url, request.method))
        if request.full_url.endswith("/healthz"):
            return Response(health)
        if request.full_url.endswith("/readyz"):
            return Response(ready)
        raise AssertionError("unexpected endpoint")
    return open_request


def test_correct_multifactor_identity_passes_without_version():
    target = identity.discover(runner())
    calls = []
    identity.verify_health(target, opener(calls=calls))
    assert [url.rsplit("/", 1)[-1] for url, _ in calls] == ["healthz", "readyz"]
    assert all(method == "GET" for _, method in calls)


@pytest.mark.parametrize(
    "mutation",
    ["image", "image_id", "service", "project", "name", "legacy_image", "public_ip",
     "loopback_ip", "missing_network", "oneoff", "image_label", "not_running"],
)
def test_container_identity_mutations_fail(mutation):
    value = copy.deepcopy(container())
    if mutation == "image":
        value["Config"]["Image"] = "codestra/middleware@sha256:" + "0" * 64
    elif mutation == "image_id":
        value["Image"] = "sha256:" + "0" * 64
    elif mutation == "service":
        value["Config"]["Labels"]["com.docker.compose.service"] = "middleware"
    elif mutation == "project":
        value["Config"]["Labels"]["com.docker.compose.project"] = "codestra"
    elif mutation == "name":
        value["Name"] = "/" + identity.LEGACY_CONTAINER
    elif mutation == "legacy_image":
        value["Config"]["Image"] = identity.LEGACY_IMAGE_PREFIX + "20260726"
    elif mutation == "public_ip":
        value["NetworkSettings"]["Networks"][identity.EXPECTED_NETWORK]["IPAddress"] = "8.8.8.8"
    elif mutation == "loopback_ip":
        value["NetworkSettings"]["Networks"][identity.EXPECTED_NETWORK]["IPAddress"] = "127.0.0.1"
    elif mutation == "missing_network":
        value["NetworkSettings"]["Networks"] = {}
    elif mutation == "image_label":
        value["Config"]["Labels"]["com.docker.compose.image"] = "sha256:" + "0" * 64
    elif mutation == "not_running":
        value["State"]["Running"] = False
    else:
        value["Config"]["Labels"]["com.docker.compose.oneoff"] = "True"
    with pytest.raises(identity.IdentityError):
        identity.discover(runner(value))


def test_ambiguous_and_missing_candidates_fail():
    with pytest.raises(identity.IdentityError):
        identity.discover(runner(candidates=[]))
    with pytest.raises(identity.IdentityError):
        identity.discover(runner(candidates=["one", "two"]))


def test_non_internal_network_fails():
    with pytest.raises(identity.IdentityError):
        identity.discover(runner(internal=False))


@pytest.mark.parametrize(
    "health,ready",
    [
        ({"status": "ok"}, identity.READY_BODY),
        ({"status": "ok", "service": identity.EXPECTED_SERVICE, "extra": "x"}, identity.READY_BODY),
        (identity.HEALTH_BODY, {"status": "not-ready", "service": identity.EXPECTED_SERVICE,
                               "authorization": "online", "delivery": "disabled"}),
        (identity.HEALTH_BODY, {"status": "ready", "service": "middleware",
                               "authorization": "online", "delivery": "disabled"}),
        (identity.HEALTH_BODY, {**identity.READY_BODY, "extra": "x"}),
    ],
)
def test_health_and_readiness_schema_fail_closed(health, ready):
    with pytest.raises(identity.IdentityError):
        identity.verify_health(identity.discover(runner()), opener(health, ready))


def test_non_200_redirect_timeout_and_refusal_fail():
    target = identity.discover(runner())

    def redirect(*_args, **_kwargs):
        raise urllib.error.HTTPError("url", 302, "redirect", {}, None)
    with pytest.raises(identity.IdentityError, match="redirect"):
        identity.verify_health(target, redirect)

    for error in (TimeoutError(), urllib.error.URLError("refused"), socket.timeout()):
        def unavailable(*_args, _error=error, **_kwargs):
            raise _error
        with pytest.raises(identity.IdentityError):
            identity.verify_health(target, unavailable)


def test_health_only_legacy_false_positive_fails_before_http():
    value = copy.deepcopy(container())
    value["Name"] = "/" + identity.LEGACY_CONTAINER
    calls = []
    with pytest.raises(identity.IdentityError):
        target = identity.discover(runner(value))
        identity.verify_health(target, opener(calls=calls))
    assert calls == []
