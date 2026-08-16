"""Read-only OpenStack SDK adapter."""

from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Mapping
from ipaddress import IPv4Address
from typing import Any

from openstack.connection import Connection
from starlette.concurrency import run_in_threadpool

from app import __version__
from app.config import Settings
from app.models.openstack import FlavorInfo, ServerInfo
from app.services.openstack import normalise_mac

log = logging.getLogger(__name__)


def build_sdk_lookup(settings: Settings) -> "SDKOpenStack":
    connection = Connection(
        app_name="snmp-metrics-api",
        app_version=__version__,
        auth_type="v3applicationcredential",
        auth={
            "auth_url": settings.os_auth_url,
            "application_credential_id": settings.os_application_credential_id,
            "application_credential_secret": (
                settings.os_application_credential_secret.get_secret_value()
            ),
        },
        region_name=settings.os_region_name or None,
        interface=settings.os_interface,
        cacert=settings.os_cacert or None,
        api_timeout=settings.openstack_api_timeout_seconds,
        compute_api_version="2",
        compute_default_microversion="2.47",
    )
    return SDKOpenStack(connection, network_name=settings.openstack_network_name)


class SDKOpenStack:
    """Translate read-only SDK responses into the application's fleet contract."""

    def __init__(self, connection: Any, network_name: str) -> None:
        self._connection = connection
        self._network_name = network_name

    async def servers(self) -> list[ServerInfo]:
        # SDK iterators perform blocking HTTP requests while they are consumed,
        # so the complete lookup belongs in the worker thread.
        return await run_in_threadpool(self._load_servers)

    def close(self) -> None:
        self._connection.close()

    def _load_servers(self) -> list[ServerInfo]:
        projects = {
            str(project.id): str(project.name)
            for project in self._connection.identity.projects()
            if project.id and project.name
        }
        users = {
            str(user.id): str(user.name)
            for user in self._connection.identity.users()
            if user.id and user.name
        }

        discovered: list[tuple[Any, tuple[str, str]]] = []
        for server in self._connection.compute.servers(
            details=True, all_projects=True
        ):
            target = _management_target(server.addresses, self._network_name)
            if target is None:
                log.warning(
                    "openstack server %s skipped: expected one fixed IPv4 with a "
                    "MAC on network %r",
                    server.id,
                    self._network_name,
                )
                continue
            discovered.append((server, target))

        mac_counts = Counter(target[0] for _, target in discovered)
        ipv4_counts = Counter(target[1] for _, target in discovered)
        result: list[ServerInfo] = []
        for server, target in discovered:
            if mac_counts[target[0]] > 1 or ipv4_counts[target[1]] > 1:
                log.warning(
                    "openstack server %s skipped: MAC %s or IPv4 %s is shared by "
                    "multiple servers",
                    server.id,
                    target[0],
                    target[1],
                )
                continue
            project_id = str(server.project_id)
            user_id = str(server.user_id)
            if project_id not in projects or user_id not in users:
                log.warning(
                    "openstack server %s skipped: project %s or user %s is not "
                    "visible in Keystone",
                    server.id,
                    project_id,
                    user_id,
                )
                continue
            flavor = _flavor_info(server.flavor)
            if flavor is None:
                log.warning(
                    "openstack server %s skipped: Nova did not return embedded "
                    "flavor details",
                    server.id,
                )
                continue
            result.append(
                ServerInfo(
                    server_id=str(server.id),
                    name=str(server.name),
                    tenant_name=projects[project_id],
                    user_name=users[user_id],
                    status=str(server.status),
                    mac=target[0],
                    ipv4=target[1],
                    flavor=flavor,
                )
            )
        return result


def _management_target(
    addresses: Any, network_name: str
) -> tuple[str, str] | None:
    if not isinstance(addresses, Mapping):
        return None
    candidates: set[tuple[str, str]] = set()
    for address in addresses.get(network_name, []):
        if _value(address, "version") != 4:
            continue
        if _value(address, "OS-EXT-IPS:type") != "fixed":
            continue
        raw_ip = _value(address, "addr")
        raw_mac = _value(address, "OS-EXT-IPS-MAC:mac_addr")
        if not raw_ip or not raw_mac:
            continue
        try:
            ipv4 = str(IPv4Address(str(raw_ip)))
        except ValueError:
            continue
        mac = normalise_mac(str(raw_mac))
        if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) is None:
            continue
        candidates.add((mac, ipv4))
    if len(candidates) != 1:
        return None
    return candidates.pop()


def _flavor_info(flavor: Any) -> FlavorInfo | None:
    name = _value(flavor, "original_name") or _value(flavor, "name")
    vcpus = _value(flavor, "vcpus")
    ram = _value(flavor, "ram")
    disk = _value(flavor, "disk")
    if not name or vcpus is None or ram is None or disk is None:
        return None
    try:
        parsed_vcpus = int(vcpus)
        parsed_ram = int(ram)
        parsed_disk = int(disk)
    except (TypeError, ValueError):
        return None
    if parsed_vcpus <= 0 or parsed_ram <= 0 or parsed_disk < 0:
        return None
    return FlavorInfo(
        name=str(name),
        vcpus=parsed_vcpus,
        ram_mb=parsed_ram,
        disk_gb=parsed_disk,
    )


def _value(resource: Any, name: str) -> Any:
    if isinstance(resource, Mapping):
        return resource.get(name)
    return getattr(resource, name, None)
