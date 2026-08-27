"""Disabled-by-default evidence adapters with explicit network security controls."""

from __future__ import annotations

import importlib
import ipaddress
import json
import socket
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta
from email.message import Message
from typing import Protocol, cast
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
import jwt
from pydantic import AwareDatetime, Field, JsonValue, ValidationError

from aegis_framework.domain import Identifier, StrictModel, stable_id
from aegis_framework.errors import (
    ConnectorDisabled,
    ConnectorRateLimited,
    ConnectorRejected,
    EvidenceUnavailable,
)
from aegis_framework.evidence import (
    ConnectorPage,
    ConnectorRecord,
    EvidenceQuery,
    EvidenceSourceKind,
)

_TEXT_TYPES = frozenset(
    {"text/markdown", "text/plain", "application/yaml", "application/x-yaml"}
)


class SecretLease(StrictModel):
    tenant_id: Identifier
    reference: Identifier
    version: int = Field(ge=1)
    value: str = Field(min_length=1, max_length=32_768, repr=False)
    expires_at: AwareDatetime


class SecretResolver(Protocol):
    def resolve(
        self,
        *,
        tenant_id: str,
        reference: str,
        expected_version: int,
    ) -> SecretLease: ...


class HostResolver(Protocol):
    def resolve(self, host: str, port: int) -> Sequence[str]: ...


class SocketHostResolver:
    def resolve(self, host: str, port: int) -> Sequence[str]:
        try:
            return tuple(
                sorted(
                    {
                        str(item[4][0])
                        for item in socket.getaddrinfo(
                            host,
                            port,
                            type=socket.SOCK_STREAM,
                        )
                    }
                )
            )
        except socket.gaierror as exc:
            raise ConnectorRejected("connector host DNS resolution failed") from exc


class NetworkPolicy(StrictModel):
    base_url: str = Field(min_length=8, max_length=512)
    allowed_hosts: tuple[str, ...] = Field(min_length=1, max_length=16)
    allowed_cidrs: tuple[str, ...] = Field(default=(), max_length=16)
    allowed_content_types: tuple[str, ...] = Field(min_length=1, max_length=16)


class HttpResponse(StrictModel):
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str]
    content: bytes


class HttpTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
        maximum_bytes: int,
        content: bytes | None = None,
    ) -> HttpResponse: ...


class HttpxTransport:
    """Thin transport adapter. Redirects and SDK retries are always disabled."""

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
        maximum_bytes: int,
        content: bytes | None = None,
    ) -> HttpResponse:
        timeout = httpx.Timeout(
            timeout_seconds,
            connect=min(timeout_seconds, 5.0),
            pool=min(timeout_seconds, 5.0),
        )
        try:
            with self._client.stream(
                method,
                url,
                headers=dict(headers),
                content=content,
                timeout=timeout,
            ) as response:
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared = int(content_length)
                    except ValueError as exc:
                        raise ConnectorRejected(
                            "connector response content length is malformed"
                        ) from exc
                    if declared < 0 or declared > maximum_bytes:
                        raise ConnectorRejected("connector response is oversized")
                chunks: list[bytes] = []
                observed = 0
                for chunk in response.iter_bytes():
                    observed += len(chunk)
                    if observed > maximum_bytes:
                        raise ConnectorRejected("connector response is oversized")
                    chunks.append(chunk)
                return HttpResponse(
                    status_code=response.status_code,
                    headers={
                        str(key).lower(): str(value)
                        for key, value in response.headers.items()
                    },
                    content=b"".join(chunks),
                )
        except ConnectorRejected:
            raise
        except httpx.TimeoutException as exc:
            raise EvidenceUnavailable("connector request timed out") from exc
        except httpx.HTTPError as exc:
            raise EvidenceUnavailable("connector transport failed") from exc


class SecureHttpClient:
    def __init__(
        self,
        *,
        policy: NetworkPolicy,
        transport: HttpTransport,
        resolver: HostResolver | None = None,
    ) -> None:
        self._policy = policy
        self._transport = transport
        self._resolver = resolver or SocketHostResolver()
        base = urlsplit(policy.base_url)
        if (
            base.scheme != "https"
            or base.username is not None
            or base.password is not None
            or not base.hostname
            or base.query
            or base.fragment
            or base.hostname.lower()
            not in {host.lower() for host in policy.allowed_hosts}
        ):
            raise ValueError("connector base URL is not a permitted HTTPS origin")
        self._origin = (
            base.scheme,
            base.hostname.lower(),
            base.port or 443,
        )
        self._allowed_networks = tuple(
            ipaddress.ip_network(cidr, strict=True) for cidr in policy.allowed_cidrs
        )

    def get_json(
        self,
        *,
        path: str,
        query: Sequence[tuple[str, str]],
        headers: Mapping[str, str],
        timeout_seconds: float,
        maximum_bytes: int,
        cancelled: Callable[[], bool],
    ) -> tuple[JsonValue, HttpResponse]:
        if cancelled():
            raise ConnectorRejected("connector request was cancelled")
        url = self._url(path=path, query=query)
        self._validate_dns()
        response = self._transport.request(
            method="GET",
            url=url,
            headers=headers,
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
            content=None,
        )
        if cancelled():
            raise ConnectorRejected("connector result was cancelled")
        self._validate_response(response, maximum_bytes=maximum_bytes)
        try:
            value = json.loads(response.content)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
        ) as exc:
            raise ConnectorRejected("connector returned malformed JSON") from exc
        return value, response

    def post_json(
        self,
        *,
        path: str,
        body: Mapping[str, JsonValue],
        headers: Mapping[str, str],
        timeout_seconds: float,
        maximum_bytes: int,
        cancelled: Callable[[], bool],
    ) -> tuple[dict[str, JsonValue], HttpResponse]:
        if cancelled():
            raise ConnectorRejected("connector request was cancelled")
        url = self._url(path=path, query=())
        self._validate_dns()
        encoded = json.dumps(
            body,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        response = self._transport.request(
            method="POST",
            url=url,
            headers={
                **headers,
                "content-type": "application/json",
                "x-aegis-body-sha256": __import__("hashlib")
                .sha256(encoded)
                .hexdigest(),
            },
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
            content=encoded,
        )
        self._validate_response(response, maximum_bytes=maximum_bytes)
        try:
            value = json.loads(response.content)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
        ) as exc:
            raise ConnectorRejected("connector returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise ConnectorRejected("connector JSON root must be an object")
        return value, response

    def validate_destination(self) -> None:
        self._validate_dns()

    def _url(self, *, path: str, query: Sequence[tuple[str, str]]) -> str:
        if (
            not path.startswith("/")
            or path.startswith("//")
            or "\\" in path
            or "\x00" in path
        ):
            raise ConnectorRejected("connector path is invalid")
        base = urlsplit(self._policy.base_url)
        joined = urlsplit(urljoin(self._policy.base_url.rstrip("/") + "/", path[1:]))
        origin = (joined.scheme, (joined.hostname or "").lower(), joined.port or 443)
        if (
            origin != self._origin
            or joined.username is not None
            or joined.password is not None
            or joined.fragment
        ):
            raise ConnectorRejected("connector URL escaped its configured origin")
        return urlunsplit(
            (
                base.scheme,
                base.netloc,
                joined.path,
                urlencode(tuple(query)),
                "",
            )
        )

    def _validate_dns(self) -> None:
        _, host, port = self._origin
        addresses = self._resolver.resolve(host, port)
        if not addresses:
            raise ConnectorRejected("connector host has no DNS address")
        for raw in addresses:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise ConnectorRejected(
                    "connector DNS returned an invalid address"
                ) from exc
            if address.is_global:
                continue
            if any(address in network for network in self._allowed_networks):
                continue
            raise ConnectorRejected("connector DNS resolved to a non-public address")

    def _validate_response(self, response: HttpResponse, *, maximum_bytes: int) -> None:
        if 300 <= response.status_code < 400:
            raise ConnectorRejected("connector redirects are disabled")
        if response.status_code in {429, 403} and (
            response.headers.get("retry-after")
            or response.headers.get("x-ratelimit-remaining") == "0"
        ):
            raise ConnectorRateLimited("connector rate limit was reached")
        if response.status_code < 200 or response.status_code >= 300:
            raise EvidenceUnavailable("connector returned a non-success status")
        if len(response.content) > maximum_bytes:
            raise ConnectorRejected("connector response is oversized")
        content_type = _media_type(response.headers.get("content-type"))
        if content_type not in self._policy.allowed_content_types:
            raise ConnectorRejected(
                "connector response content type is not allowlisted"
            )


class EvidenceConnector(Protocol):
    kind: EvidenceSourceKind

    def fetch_page(
        self,
        query: EvidenceQuery,
        *,
        cursor: str | None,
        page_number: int,
        cancelled: Callable[[], bool],
    ) -> ConnectorPage: ...


class DynatraceConnector:
    kind = EvidenceSourceKind.DYNATRACE

    def __init__(
        self,
        *,
        client: SecureHttpClient,
        secrets: SecretResolver,
        clock: Callable[[], datetime],
        enabled: bool = False,
    ) -> None:
        self._client = client
        self._secrets = secrets
        self._clock = clock
        self._enabled = enabled

    def fetch_page(
        self,
        query: EvidenceQuery,
        *,
        cursor: str | None,
        page_number: int,
        cancelled: Callable[[], bool],
    ) -> ConnectorPage:
        _require_query(query, kind=self.kind, enabled=self._enabled)
        source = query.source
        if source.credential_ref is None or source.credential_version is None:
            raise ConnectorRejected("Dynatrace source has no credential binding")
        secret = self._secrets.resolve(
            tenant_id=query.tenant_id,
            reference=source.credential_ref,
            expected_version=source.credential_version,
        )
        _validate_secret(secret, query)
        parameters = (
            (("nextPageKey", cursor),)
            if cursor is not None
            else (
                ("from", query.window.start.isoformat()),
                ("to", query.window.end.isoformat()),
                ("pageSize", str(min(query.bounds.maximum_records, 1_000))),
            )
        )
        body, response = self._client.get_json(
            path=f"/api/v2/{query.resource}",
            query=parameters,
            headers={
                "accept": "application/json",
                "authorization": f"Api-Token {secret.value}",
            },
            timeout_seconds=query.bounds.request_timeout_seconds,
            maximum_bytes=query.bounds.maximum_page_bytes,
            cancelled=cancelled,
        )
        if not isinstance(body, dict):
            raise ConnectorRejected("Dynatrace JSON root must be an object")
        records = _json_records(
            body.get("result", body.get("values", [])),
            query=query,
            page_number=page_number,
            locator_prefix="dynatrace",
            observed_at=query.window.end,
        )
        return _build_connector_page(
            query_id=query.query_id,
            source_id=source.source_id,
            page_number=page_number,
            records=records,
            next_cursor=_optional_string(body.get("nextPageKey")),
            response_bytes=max(
                len(response.content),
                sum(len(record.payload) for record in records),
            ),
            rate_limit_remaining=_optional_int(
                response.headers.get("x-ratelimit-remaining")
            ),
            retrieved_at=self._clock(),
        )


class GitHubAppConfig(StrictModel):
    app_id: int = Field(gt=0)
    installation_id: int = Field(gt=0)
    repositories: tuple[str, ...] = Field(min_length=1, max_length=500)
    permissions: dict[str, str] = Field(default_factory=dict, max_length=32)


class GitHubAppConnector:
    kind = EvidenceSourceKind.GITHUB

    def __init__(
        self,
        *,
        client: SecureHttpClient,
        secrets: SecretResolver,
        config: GitHubAppConfig,
        clock: Callable[[], datetime],
        enabled: bool = False,
    ) -> None:
        self._client = client
        self._secrets = secrets
        self._config = config
        self._clock = clock
        self._enabled = enabled

    def fetch_page(
        self,
        query: EvidenceQuery,
        *,
        cursor: str | None,
        page_number: int,
        cancelled: Callable[[], bool],
    ) -> ConnectorPage:
        _require_query(query, kind=self.kind, enabled=self._enabled)
        source = query.source
        if source.credential_ref is None or source.credential_version is None:
            raise ConnectorRejected("GitHub source has no credential binding")
        owner, repository, resource = _github_resource(query.resource)
        full_name = f"{owner}/{repository}"
        if full_name not in self._config.repositories:
            raise ConnectorRejected("GitHub repository is not installation-allowlisted")
        secret = self._secrets.resolve(
            tenant_id=query.tenant_id,
            reference=source.credential_ref,
            expected_version=source.credential_version,
        )
        _validate_secret(secret, query)
        token = self._installation_token(secret, cancelled=cancelled)
        page = int(cursor) if cursor is not None and cursor.isdigit() else page_number
        if page < 1 or page > query.bounds.maximum_pages:
            raise ConnectorRejected("GitHub cursor is outside the page bound")
        body, response = self._client.get_json(
            path=f"/repos/{owner}/{repository}/{resource}",
            query=(("per_page", "100"), ("page", str(page))),
            headers={
                "accept": "application/vnd.github+json",
                "authorization": f"Bearer {token}",
                "x-github-api-version": "2022-11-28",
            },
            timeout_seconds=query.bounds.request_timeout_seconds,
            maximum_bytes=query.bounds.maximum_page_bytes,
            cancelled=cancelled,
        )
        raw_records = (
            body.get("items", body.get("deployments", body.get("values", [])))
            if isinstance(body, dict)
            else body
        )
        records = _json_records(
            raw_records,
            query=query,
            page_number=page_number,
            locator_prefix=f"github:{full_name}",
            observed_at=query.window.end,
        )
        next_cursor = _github_next_page(response.headers.get("link"))
        return _build_connector_page(
            query_id=query.query_id,
            source_id=source.source_id,
            page_number=page_number,
            records=records,
            next_cursor=next_cursor,
            response_bytes=max(
                len(response.content),
                sum(len(record.payload) for record in records),
            ),
            rate_limit_remaining=_optional_int(
                response.headers.get("x-ratelimit-remaining")
            ),
            retrieved_at=self._clock(),
        )

    def _installation_token(
        self,
        secret: SecretLease,
        *,
        cancelled: Callable[[], bool],
    ) -> str:
        now = self._clock()
        app_token = jwt.encode(
            {
                "iat": int((now - timedelta(seconds=30)).timestamp()),
                "exp": int((now + timedelta(minutes=9)).timestamp()),
                "iss": str(self._config.app_id),
            },
            secret.value,
            algorithm="RS256",
        )
        body, _ = self._client.post_json(
            path=f"/app/installations/{self._config.installation_id}/access_tokens",
            body={
                "repositories": [
                    full_name.split("/", maxsplit=1)[1]
                    for full_name in self._config.repositories
                ],
                "permissions": dict(sorted(self._config.permissions.items())),
            },
            headers={
                "accept": "application/vnd.github+json",
                "authorization": f"Bearer {app_token}",
                "x-github-api-version": "2022-11-28",
            },
            timeout_seconds=10.0,
            maximum_bytes=65_536,
            cancelled=cancelled,
        )
        token = body.get("token")
        if not isinstance(token, str) or not token or len(token) > 512:
            raise ConnectorRejected("GitHub installation token response is malformed")
        return token


class KubernetesListResponse(Protocol):
    items: Sequence[object]
    metadata: object


class KubernetesApi(Protocol):
    def list_namespaced_event(
        self,
        namespace: str,
        *,
        limit: int,
        _continue: str | None,
        field_selector: str | None,
        label_selector: str | None,
        timeout_seconds: int,
        _request_timeout: tuple[float, float],
    ) -> KubernetesListResponse: ...


class KubernetesConnector:
    kind = EvidenceSourceKind.KUBERNETES

    def __init__(
        self,
        *,
        api: KubernetesApi,
        namespaces: Sequence[str],
        clock: Callable[[], datetime],
        enabled: bool = False,
    ) -> None:
        self._api = api
        self._namespaces = frozenset(namespaces)
        self._clock = clock
        self._enabled = enabled

    def fetch_page(
        self,
        query: EvidenceQuery,
        *,
        cursor: str | None,
        page_number: int,
        cancelled: Callable[[], bool],
    ) -> ConnectorPage:
        _require_query(query, kind=self.kind, enabled=self._enabled)
        namespace, resource = _kubernetes_resource(query.resource)
        if namespace not in self._namespaces or resource != "events":
            raise ConnectorRejected("Kubernetes resource is not allowlisted")
        if cancelled():
            raise ConnectorRejected("connector request was cancelled")
        try:
            response = self._api.list_namespaced_event(
                namespace,
                limit=min(query.bounds.maximum_records, 500),
                _continue=cursor,
                field_selector=_optional_parameter(query, "field_selector"),
                label_selector=_optional_parameter(query, "label_selector"),
                timeout_seconds=max(
                    1, min(int(query.bounds.request_timeout_seconds), 120)
                ),
                _request_timeout=(
                    min(query.bounds.request_timeout_seconds, 5.0),
                    query.bounds.request_timeout_seconds,
                ),
            )
        except Exception as exc:
            status = getattr(exc, "status", None)
            if status == 410:
                raise ConnectorRejected(
                    "Kubernetes continue token expired; reconciliation must relist"
                ) from exc
            raise EvidenceUnavailable("Kubernetes SDK request failed") from exc
        if cancelled():
            raise ConnectorRejected("connector result was cancelled")
        records: list[ConnectorRecord] = []
        total = 0
        for index, item in enumerate(response.items):
            payload = _kubernetes_json(item)
            total += len(payload)
            if total > query.bounds.maximum_page_bytes:
                raise ConnectorRejected("Kubernetes page is oversized")
            records.append(
                ConnectorRecord(
                    record_id=stable_id(
                        "record",
                        query.query_id,
                        str(page_number),
                        str(index),
                    ),
                    locator=(
                        f"kubernetes://{namespace}/{resource}/{page_number}/{index}"
                    ),
                    observed_at=query.window.end,
                    content_type="application/json",
                    payload=payload,
                )
            )
        metadata = getattr(response, "metadata", None)
        next_cursor = getattr(metadata, "_continue", None)
        if next_cursor is not None and not isinstance(next_cursor, str):
            raise ConnectorRejected("Kubernetes SDK returned a malformed cursor")
        return _build_connector_page(
            query_id=query.query_id,
            source_id=query.source.source_id,
            page_number=page_number,
            records=tuple(records),
            next_cursor=next_cursor or None,
            response_bytes=total,
            retrieved_at=self._clock(),
        )


class KubernetesClientConfig(StrictModel):
    tenant_id: Identifier
    server_url: str = Field(min_length=8, max_length=512)
    token_ref: Identifier
    token_version: int = Field(ge=1)
    namespaces: tuple[Identifier, ...] = Field(min_length=1, max_length=64)


def build_kubernetes_connector(
    *,
    config: KubernetesClientConfig,
    secrets: SecretResolver,
    resolver: HostResolver | None,
    clock: Callable[[], datetime],
    enabled: bool = False,
) -> KubernetesConnector:
    """Build the official client without loading executable kubeconfig plugins."""

    guard = SecureHttpClient(
        policy=NetworkPolicy(
            base_url=config.server_url,
            allowed_hosts=((urlsplit(config.server_url).hostname or "").lower(),),
            allowed_content_types=("application/json",),
        ),
        transport=HttpxTransport(),
        resolver=resolver,
    )
    guard.validate_destination()
    lease = secrets.resolve(
        tenant_id=config.tenant_id,
        reference=config.token_ref,
        expected_version=config.token_version,
    )
    if (
        lease.tenant_id != config.tenant_id
        or lease.reference != config.token_ref
        or lease.version != config.token_version
        or lease.expires_at <= clock()
    ):
        raise ConnectorRejected("Kubernetes credential binding is stale or invalid")
    try:
        client_module = importlib.import_module("kubernetes.client")
        configuration = client_module.Configuration()
        configuration.host = config.server_url
        configuration.api_key["authorization"] = lease.value
        configuration.api_key_prefix["authorization"] = "Bearer"
        configuration.retries = 0
        configuration.assert_hostname = True
        api_client = client_module.ApiClient(configuration=configuration)
        api = client_module.CoreV1Api(api_client)
    except (AttributeError, ImportError, TypeError, ValueError) as exc:
        raise ConnectorRejected(
            "official Kubernetes client initialization failed"
        ) from exc
    return KubernetesConnector(
        api=cast(KubernetesApi, api),
        namespaces=config.namespaces,
        clock=clock,
        enabled=enabled,
    )


class RunbookObject(StrictModel):
    object_id: Identifier
    version: Identifier
    locator: str = Field(min_length=1, max_length=1_024)
    content_type: str = Field(min_length=3, max_length=128)
    content: bytes = Field(min_length=1, max_length=2 * 1024 * 1024)
    observed_at: AwareDatetime


class RunbookRepository(Protocol):
    def read(
        self,
        *,
        tenant_id: str,
        resource: str,
        version: str | None,
    ) -> RunbookObject: ...


class TrustedRunbookConnector:
    kind = EvidenceSourceKind.RUNBOOK

    def __init__(
        self,
        *,
        repository: RunbookRepository,
        clock: Callable[[], datetime],
        enabled: bool = False,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._enabled = enabled

    def fetch_page(
        self,
        query: EvidenceQuery,
        *,
        cursor: str | None,
        page_number: int,
        cancelled: Callable[[], bool],
    ) -> ConnectorPage:
        _require_query(query, kind=self.kind, enabled=self._enabled)
        if cursor is not None or page_number != 1:
            raise ConnectorRejected("runbook connector does not paginate")
        if cancelled():
            raise ConnectorRejected("connector request was cancelled")
        version = _optional_parameter(query, "version")
        item = self._repository.read(
            tenant_id=query.tenant_id,
            resource=query.resource,
            version=version,
        )
        if item.content_type not in _TEXT_TYPES or len(item.content) > (
            query.bounds.maximum_page_bytes
        ):
            raise ConnectorRejected("runbook object type or size is not allowed")
        return _build_connector_page(
            query_id=query.query_id,
            source_id=query.source.source_id,
            page_number=1,
            records=(
                ConnectorRecord(
                    record_id=stable_id(
                        "record", query.query_id, item.object_id, item.version
                    ),
                    locator=item.locator,
                    observed_at=item.observed_at,
                    content_type=item.content_type,
                    payload=item.content,
                    source_version=item.version,
                ),
            ),
            next_cursor=None,
            response_bytes=len(item.content),
            retrieved_at=self._clock(),
        )


def _require_query(
    query: EvidenceQuery,
    *,
    kind: EvidenceSourceKind,
    enabled: bool,
) -> None:
    if not enabled or not query.source.enabled:
        raise ConnectorDisabled(f"{kind.value} connector is disabled")
    if query.source.kind is not kind:
        raise ConnectorRejected("connector source kind does not match adapter")


def _build_connector_page(
    *,
    query_id: str,
    source_id: str,
    page_number: int,
    records: Sequence[ConnectorRecord],
    next_cursor: str | None,
    response_bytes: int,
    retrieved_at: datetime,
    rate_limit_remaining: int | None = None,
) -> ConnectorPage:
    try:
        return ConnectorPage(
            query_id=query_id,
            source_id=source_id,
            page_number=page_number,
            records=tuple(records),
            next_cursor=next_cursor,
            response_bytes=response_bytes,
            rate_limit_remaining=rate_limit_remaining,
            retrieved_at=retrieved_at,
        )
    except ValidationError as exc:
        raise ConnectorRejected("connector page is outside schema bounds") from exc


def _validate_secret(secret: SecretLease, query: EvidenceQuery) -> None:
    source = query.source
    if (
        secret.tenant_id != query.tenant_id
        or secret.reference != source.credential_ref
        or secret.version != source.credential_version
        or secret.expires_at <= query.created_at
    ):
        raise ConnectorRejected("connector credential binding is stale or invalid")


def _media_type(value: str | None) -> str:
    if value is None:
        return ""
    message = Message()
    message["content-type"] = value
    return message.get_content_type().lower()


def _json_records(
    value: JsonValue,
    *,
    query: EvidenceQuery,
    page_number: int,
    locator_prefix: str,
    observed_at: datetime,
) -> tuple[ConnectorRecord, ...]:
    if not isinstance(value, list):
        raise ConnectorRejected("connector collection field must be an array")
    records: list[ConnectorRecord] = []
    for index, item in enumerate(value):
        if index >= query.bounds.maximum_records:
            raise ConnectorRejected("connector record count exceeds the query bound")
        encoded = json.dumps(
            item,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        try:
            records.append(
                ConnectorRecord(
                    record_id=stable_id(
                        "record",
                        query.query_id,
                        str(page_number),
                        str(index),
                    ),
                    locator=f"{locator_prefix}/{page_number}/{index}",
                    observed_at=observed_at,
                    content_type="application/json",
                    payload=encoded,
                )
            )
        except ValidationError as exc:
            raise ConnectorRejected(
                "connector record is outside schema bounds"
            ) from exc
    return tuple(records)


def _github_resource(value: str) -> tuple[str, str, str]:
    parts = value.split("/")
    if len(parts) != 3 or parts[2] not in {"deployments", "issues", "pulls"}:
        raise ConnectorRejected("GitHub resource must be owner/repository/collection")
    if any(
        not part
        or len(part) > 100
        or not all(character.isalnum() or character in "._-" for character in part)
        for part in parts[:2]
    ):
        raise ConnectorRejected("GitHub owner or repository is invalid")
    return parts[0], parts[1], parts[2]


def _github_next_page(link: str | None) -> str | None:
    if not link:
        return None
    for section in link.split(","):
        target, *parameters = section.split(";")
        if not any('rel="next"' in parameter for parameter in parameters):
            continue
        target = target.strip()
        if not target.startswith("<") or not target.endswith(">"):
            raise ConnectorRejected("GitHub Link header is malformed")
        query = dict(parse_qsl(urlsplit(target[1:-1]).query, keep_blank_values=True))
        page = query.get("page")
        if page is None or not page.isdigit() or int(page) < 1 or int(page) > 100:
            raise ConnectorRejected("GitHub next-page cursor is invalid")
        return page
    return None


def _kubernetes_resource(value: str) -> tuple[str, str]:
    parts = value.split("/")
    if len(parts) != 2 or any(not part or len(part) > 128 for part in parts):
        raise ConnectorRejected("Kubernetes resource must be namespace/collection")
    return parts[0], parts[1]


def _kubernetes_json(value: object) -> bytes:
    if hasattr(value, "to_dict"):
        candidate = value.to_dict()
    elif isinstance(value, Mapping):
        candidate = dict(value)
    else:
        raise ConnectorRejected("Kubernetes SDK item is not serializable")
    try:
        return json.dumps(
            candidate,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            default=str,
        ).encode()
    except (TypeError, ValueError) as exc:
        raise ConnectorRejected("Kubernetes SDK item is malformed") from exc


def _optional_parameter(query: EvidenceQuery, key: str) -> str | None:
    value = query.parameters.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 512:
        raise ConnectorRejected(f"connector parameter {key} is invalid")
    return value


def _optional_string(value: JsonValue | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 4_096:
        raise ConnectorRejected("connector cursor is malformed")
    return value


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ConnectorRejected("connector numeric header is malformed")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConnectorRejected("connector numeric header is malformed") from exc
    if parsed < 0:
        raise ConnectorRejected("connector numeric header is negative")
    return parsed
