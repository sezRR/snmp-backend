from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Mapping
from ipaddress import IPv4Address
from typing import Any

import openstack
from starlette.concurrency import run_in_threadpool

from app import __version__
from app.config import Settings
from app.models.openstack import FlavorInfo, ServerInfo
from app.services.openstack import normalise_mac

log = logging.getLogger(__name__)


def build_sdk_lookup(settings: Settings) -> "SDKOpenStack":
    # Keystone v3 password auth: a UUID when OS_USER_ID is set, a
    # name-in-a-domain otherwise. Sending both would be ambiguous.
    credentials: dict[str, object] = {
        "auth_url": settings.os_auth_url,
        "password": settings.os_password.get_secret_value(),
        "project_id": settings.os_project_id,
    }
    if settings.os_user_id:
        credentials["user_id"] = settings.os_user_id
    else:
        credentials["username"] = settings.os_username
        credentials["user_domain_id"] = settings.os_user_domain_id

    connection = openstack.connect(
        app_name="snmp-metrics-api",
        app_version=__version__,
        # The environment is the only configuration source: no clouds.yaml or
        # stray OS_* may redirect the lookup at another cloud.
        load_yaml_config=False,
        load_envvars=False,
        region_name=settings.os_region_name or None,
        interface=settings.os_interface or None,
        cacert=settings.os_cacert or None,
        api_timeout=settings.openstack_api_timeout_seconds,
        compute_api_version="2",
        compute_default_microversion="2.47",
        **credentials,
    )
    return SDKOpenStack(connection)


class SDKOpenStack:
    """Translate read-only SDK responses into the application's fleet contract."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    async def servers(self) -> list[ServerInfo]:
        # SDK iterators do blocking HTTP as they are consumed.
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
            target = _management_target(server.addresses)
            if target is None:
                log.warning(
                    "openstack server %s skipped: no fixed IPv4 with a MAC on "
                    "any of its networks",
                    server.id,
                )
                continue
            discovered.append((server, target))

        subnet_names = self._subnet_names_by_port_ip() if discovered else {}

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
                    subnet_name=subnet_names.get(target),
                    flavor=flavor,
                )
            )
        return result

    def _subnet_names_by_port_ip(self) -> dict[tuple[str, str], str]:
        """`(mac, ipv4)` -> subnet name, from Neutron.

        Nova's address entry carries no subnet, so the name has to come from the
        port that owns the address. Both listings are fleet-wide and run once per
        cache refresh rather than once per server, which is what keeps this to two
        extra calls per TTL window instead of two per machine.

        Descriptive data only: a Neutron failure — no `network:list` role, an
        endpoint missing from the catalog — costs the label and nothing else, so
        it is logged and swallowed rather than failing the whole refresh.
        """
        try:
            subnets = {
                str(subnet.id): str(subnet.name)
                for subnet in self._connection.network.subnets()
                if subnet.id and subnet.name
            }
            names: dict[tuple[str, str], str] = {}
            for port in self._connection.network.ports():
                raw_mac = _value(port, "mac_address")
                if not raw_mac:
                    continue
                mac = normalise_mac(str(raw_mac))
                for fixed_ip in _value(port, "fixed_ips") or []:
                    ip = _value(fixed_ip, "ip_address")
                    name = subnets.get(str(_value(fixed_ip, "subnet_id")))
                    if ip and name:
                        names[(mac, str(ip))] = name
            return names
        except Exception as exc:  # network call; the label is not load-bearing
            log.warning(
                "openstack subnet names unavailable (%s: %s); servers will be "
                "returned without one",
                type(exc).__name__,
                exc,
            )
            return {}


def _management_target(addresses: Any) -> tuple[str, str] | None:
    """First usable fixed IPv4/MAC pair Nova lists, across every network.

    No network is singled out: every network the server is attached to is walked
    in the order Nova returns them, and the first fixed IPv4 carrying a MAC wins.
    Nova's ordering is stable, so "the first" is the same address on every
    refresh — but a server rewired onto a new network ahead of its old one will
    be tracked at the new address, which is the cost of not naming a network.

    Floating IPs are still ignored: only a fixed address belongs to the port
    whose MAC the collector joins on.
    """
    if not isinstance(addresses, Mapping):
        return None
    for network_addresses in addresses.values():
        for address in network_addresses or []:
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
            return (mac, ipv4)
    return None


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
