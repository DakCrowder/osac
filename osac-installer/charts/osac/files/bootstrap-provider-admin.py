"""Create the first provider administrator through the private Fulfillment API."""
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://fulfillment-internal-api:8001/api/private/v1"
ROLE_ID = "019dd9f6-36cb-7824-ac1c-6455d8a7a9b5"
USERNAME = os.environ["OSAC_BOOTSTRAP_USERNAME"]
TLS = ssl.create_default_context(cafile="/etc/ca-bundle/bundle.pem")
DEADLINE = time.monotonic() + 300


def request(path, body=None):
    headers = {"Authorization": "Bearer " + os.environ["OSAC_BOOTSTRAP_TOKEN"]}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    query = urllib.request.Request(API + path, data=data, headers=headers)
    with urllib.request.urlopen(query, context=TLS, timeout=10) as response:
        return json.load(response)


def ensure(path, filter_, body):
    endpoint = path + "?" + urllib.parse.urlencode({"filter": filter_, "limit": 2})
    items = request(endpoint).get("items", [])
    if len(items) > 1:
        raise RuntimeError("ambiguous bootstrap resource")
    if items:
        return items[0]
    try:
        return request(path, body)
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise
        items = request(endpoint).get("items", [])
        if len(items) != 1:
            raise RuntimeError("bootstrap resource conflicts with an existing resource") from error
        return items[0]


def wait_for(path, resource, predicate, message):
    while not predicate(resource):
        if time.monotonic() >= DEADLINE:
            raise RuntimeError(message)
        time.sleep(3)
        resource = request(path)
    return resource


def main():
    username_filter = json.dumps(USERNAME)
    user = ensure(
        "/users",
        f'this.metadata.tenant == "system" && this.spec.username == {username_filter}'
        " && this.metadata.deletion_timestamp == null",
        {"metadata": {"name": "provider-admin", "tenant": "system"},
         "spec": {"username": USERNAME, "enabled": True}},
    )
    if not user.get("spec", {}).get("enabled"):
        raise RuntimeError("bootstrap User is disabled")

    def has_keycloak_identity(user):
        status = user.get("status", {})
        return status.get("keycloak_user_id") or status.get("keycloakUserId")

    user = wait_for(
        "/users/" + user["id"], user, has_keycloak_identity,
        "configured provider administrator did not resolve to a Keycloak user",
    )
    binding = ensure(
        "/role_bindings",
        'this.metadata.tenant == "system" && this.metadata.name == "bootstrap-provider-admin"'
        " && this.metadata.deletion_timestamp == null",
        {"metadata": {"name": "bootstrap-provider-admin", "tenant": "system"},
         "spec": {"role": {"id": ROLE_ID, "tenant": "shared"},
                  "users": [{"id": user["id"]}]}},
    )
    spec = binding.get("spec", {})
    if spec.get("role", {}).get("id") != ROLE_ID or [u["id"] for u in spec.get("users", [])] != [user["id"]]:
        raise RuntimeError("bootstrap RoleBinding has unexpected contents")
    wait_for(
        "/role_bindings/" + binding["id"], binding,
        lambda resource: resource.get("status", {}).get("state") == "ROLE_BINDING_STATE_READY",
        "provider RoleBinding did not synchronize to Keycloak",
    )


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        raise SystemExit(f"Provider administrator bootstrap failed: {error}") from None
