import threading
from types import SimpleNamespace
from typing import Any
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import Mock, patch

from pydantic import ValidationError

from app.config import Settings
from app.services.openstack import CachedOpenStack, build_lookup
from app.services.openstack.sdk import SDKOpenStack, build_sdk_lookup


def sdk_server(**attrs: Any) -> SimpleNamespace:
    return SimpleNamespace(**attrs)


def sdk_network(
    subnets: list[SimpleNamespace] | None = None,
    ports: list[SimpleNamespace] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        subnets=Mock(return_value=iter(subnets or [])),
        ports=Mock(return_value=iter(ports or [])),
    )


class SDKOpenStackTests(IsolatedAsyncioTestCase):
    async def test_servers_returns_existing_contract_from_read_only_lookups(
        self,
    ) -> None:
        caller_thread = threading.get_ident()
        sdk_thread: list[int] = []

        def servers(**query: object):
            sdk_thread.append(threading.get_ident())
            self.assertEqual(query, {"details": True, "all_projects": True})
            return iter(
                [
                    sdk_server(
                        id="server-1",
                        name="web-01",
                        project_id="project-1",
                        user_id="user-1",
                        status="ACTIVE",
                        addresses={
                            "management": [
                                {
                                    "addr": "10.0.0.11",
                                    "version": 4,
                                    "OS-EXT-IPS:type": "fixed",
                                    "OS-EXT-IPS-MAC:mac_addr": "FA-16-3E-00-00-01",
                                }
                            ],
                            "public": [
                                {
                                    "addr": "192.0.2.11",
                                    "version": 4,
                                    "OS-EXT-IPS:type": "floating",
                                    "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:01",
                                }
                            ],
                        },
                        flavor={
                            "original_name": "m1.small",
                            "vcpus": 1,
                            "ram": 2048,
                            "disk": 20,
                        },
                    )
                ]
            )

        connection = SimpleNamespace(
            compute=SimpleNamespace(servers=Mock(side_effect=servers)),
            identity=SimpleNamespace(
                projects=Mock(
                    return_value=iter(
                        [SimpleNamespace(id="project-1", name="acme-prod")]
                    )
                ),
                users=Mock(
                    return_value=iter([SimpleNamespace(id="user-1", name="alice")])
                ),
            ),
            network=sdk_network(
                subnets=[
                    SimpleNamespace(id="subnet-1", name="prod-mgmt"),
                    SimpleNamespace(id="subnet-2", name="prod-storage"),
                ],
                ports=[
                    SimpleNamespace(
                        mac_address="FA:16:3E:00:00:01",
                        fixed_ips=[
                            {"ip_address": "10.0.0.11", "subnet_id": "subnet-1"}
                        ],
                    ),
                    SimpleNamespace(
                        mac_address="fa:16:3e:00:00:09",
                        fixed_ips=[
                            {"ip_address": "10.9.0.9", "subnet_id": "subnet-2"}
                        ],
                    ),
                ],
            ),
            close=Mock(),
        )

        lookup = SDKOpenStack(connection)

        result = await lookup.servers()

        self.assertEqual(
            [server.model_dump() for server in result],
            [
                {
                    "server_id": "server-1",
                    "name": "web-01",
                    "tenant_name": "acme-prod",
                    "user_name": "alice",
                    "status": "ACTIVE",
                    "mac": "fa:16:3e:00:00:01",
                    "ipv4": "10.0.0.11",
                    "subnet_name": "prod-mgmt",
                    "flavor": {
                        "name": "m1.small",
                        "vcpus": 1,
                        "ram_mb": 2048,
                        "disk_gb": 20,
                    },
                }
            ],
        )
        self.assertEqual(len(sdk_thread), 1)
        self.assertNotEqual(sdk_thread[0], caller_thread)
        connection.identity.projects.assert_called_once_with()
        connection.identity.users.assert_called_once_with()

    async def test_servers_skips_partial_or_unenriched_records(self) -> None:
        valid_address = {
            "management": [
                {
                    "addr": "10.0.0.11",
                    "version": 4,
                    "OS-EXT-IPS:type": "fixed",
                    "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:01",
                }
            ]
        }
        servers = [
            sdk_server(
                id="partial",
                name="partial",
                project_id="project-1",
                user_id="user-1",
                status="ACTIVE",
                addresses=None,
                flavor={
                    "original_name": "m1.small",
                    "vcpus": 1,
                    "ram": 2048,
                    "disk": 20,
                },
            ),
            sdk_server(
                id="unknown-user",
                name="unknown-user",
                project_id="project-1",
                user_id="deleted-user",
                status="ACTIVE",
                addresses=valid_address,
                flavor={
                    "original_name": "m1.small",
                    "vcpus": 1,
                    "ram": 2048,
                    "disk": 20,
                },
            ),
            sdk_server(
                id="incomplete-flavor",
                name="incomplete-flavor",
                project_id="project-1",
                user_id="user-1",
                status="ACTIVE",
                addresses={
                    "management": [
                        {
                            "addr": "10.0.0.13",
                            "version": 4,
                            "OS-EXT-IPS:type": "fixed",
                            "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:03",
                        }
                    ]
                },
                flavor={"id": "flavor-1"},
            ),
            sdk_server(
                id="unclassified-address",
                name="unclassified-address",
                project_id="project-1",
                user_id="user-1",
                status="ACTIVE",
                addresses={
                    "management": [
                        {
                            "addr": "10.0.0.12",
                            "version": 4,
                            "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:02",
                        }
                    ]
                },
                flavor={
                    "original_name": "m1.small",
                    "vcpus": 1,
                    "ram": 2048,
                    "disk": 20,
                },
            ),
        ]
        connection = SimpleNamespace(
            compute=SimpleNamespace(servers=Mock(return_value=iter(servers))),
            identity=SimpleNamespace(
                projects=Mock(
                    return_value=iter(
                        [SimpleNamespace(id="project-1", name="acme-prod")]
                    )
                ),
                users=Mock(
                    return_value=iter([SimpleNamespace(id="user-1", name="alice")])
                ),
            ),
            network=sdk_network(),
            close=Mock(),
        )

        result = await SDKOpenStack(connection).servers()

        self.assertEqual(result, [])

    async def test_servers_excludes_duplicate_cross_project_targets(self) -> None:
        def server(
            server_id: str, project_id: str, user_id: str, mac: str
        ) -> SimpleNamespace:
            return sdk_server(
                id=server_id,
                name=server_id,
                project_id=project_id,
                user_id=user_id,
                status="ACTIVE",
                addresses={
                    "management": [
                        {
                            "addr": "10.0.0.11",
                            "version": 4,
                            "OS-EXT-IPS:type": "fixed",
                            "OS-EXT-IPS-MAC:mac_addr": mac,
                        }
                    ]
                },
                flavor={
                    "original_name": "m1.small",
                    "vcpus": 1,
                    "ram": 2048,
                    "disk": 20,
                },
            )

        connection = SimpleNamespace(
            compute=SimpleNamespace(
                servers=Mock(
                    return_value=iter(
                        [
                            server(
                                "server-1",
                                "project-1",
                                "user-1",
                                "fa:16:3e:00:00:01",
                            ),
                            server(
                                "server-2",
                                "project-2",
                                "deleted-user",
                                "fa:16:3e:00:00:02",
                            ),
                        ]
                    )
                )
            ),
            identity=SimpleNamespace(
                projects=Mock(
                    return_value=iter(
                        [
                            SimpleNamespace(id="project-1", name="acme-prod"),
                            SimpleNamespace(id="project-2", name="other-prod"),
                        ]
                    )
                ),
                users=Mock(
                    return_value=iter([SimpleNamespace(id="user-1", name="alice")])
                ),
            ),
            network=sdk_network(),
            close=Mock(),
        )

        result = await SDKOpenStack(connection).servers()

        self.assertEqual(result, [])

    async def test_servers_take_the_first_fixed_address_on_any_network(self) -> None:
        server = SimpleNamespace(
            id="server-1",
            name="web-01",
            project_id="project-1",
            user_id="user-1",
            status="ACTIVE",
            addresses={
                # No network is named in the configuration, so the walk starts at
                # whichever one Nova lists first — and skips the floating address
                # on it, because only a fixed address belongs to a port.
                "public": [
                    {
                        "addr": "192.0.2.11",
                        "version": 4,
                        "OS-EXT-IPS:type": "floating",
                        "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:01",
                    }
                ],
                "management": [
                    {
                        "addr": "10.0.0.11",
                        "version": 4,
                        "OS-EXT-IPS:type": "fixed",
                        "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:01",
                    },
                    {
                        "addr": "10.0.0.12",
                        "version": 4,
                        "OS-EXT-IPS:type": "fixed",
                        "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:02",
                    },
                ],
                "storage": [
                    {
                        "addr": "10.7.0.11",
                        "version": 4,
                        "OS-EXT-IPS:type": "fixed",
                        "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:03",
                    }
                ],
            },
            flavor={
                "original_name": "m1.small",
                "vcpus": 1,
                "ram": 2048,
                "disk": 20,
            },
        )
        connection = SimpleNamespace(
            compute=SimpleNamespace(servers=Mock(return_value=iter([server]))),
            identity=SimpleNamespace(
                projects=Mock(
                    return_value=iter(
                        [SimpleNamespace(id="project-1", name="acme-prod")]
                    )
                ),
                users=Mock(
                    return_value=iter([SimpleNamespace(id="user-1", name="alice")])
                ),
            ),
            network=sdk_network(),
            close=Mock(),
        )

        result = await SDKOpenStack(connection).servers()

        self.assertEqual(
            [(server.mac, server.ipv4, server.subnet_name) for server in result],
            [("fa:16:3e:00:00:01", "10.0.0.11", None)],
        )

    async def test_servers_survive_an_unreadable_neutron(self) -> None:
        server = SimpleNamespace(
            id="server-1",
            name="web-01",
            project_id="project-1",
            user_id="user-1",
            status="ACTIVE",
            addresses={
                "management": [
                    {
                        "addr": "10.0.0.11",
                        "version": 4,
                        "OS-EXT-IPS:type": "fixed",
                        "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:01",
                    }
                ]
            },
            flavor={
                "original_name": "m1.small",
                "vcpus": 1,
                "ram": 2048,
                "disk": 20,
            },
        )
        connection = SimpleNamespace(
            compute=SimpleNamespace(servers=Mock(return_value=iter([server]))),
            identity=SimpleNamespace(
                projects=Mock(
                    return_value=iter(
                        [SimpleNamespace(id="project-1", name="acme-prod")]
                    )
                ),
                users=Mock(
                    return_value=iter([SimpleNamespace(id="user-1", name="alice")])
                ),
            ),
            network=SimpleNamespace(
                subnets=Mock(side_effect=RuntimeError("403 Forbidden")),
                ports=Mock(return_value=iter([])),
            ),
            close=Mock(),
        )

        result = await SDKOpenStack(connection).servers()

        self.assertEqual(
            [(server.ipv4, server.subnet_name) for server in result],
            [("10.0.0.11", None)],
        )

    def test_cache_close_releases_upstream_connection(self) -> None:
        upstream = SimpleNamespace(close=Mock())
        lookup = CachedOpenStack(upstream, ttl_seconds=300)

        lookup.close()

        upstream.close.assert_called_once_with()


class OpenStackSettingsTests(TestCase):
    def _settings(self, **overrides: Any) -> Settings:
        base: dict[str, Any] = {
            "_env_file": None,
            "jwt_secret": "x" * 32,
            "admin_username": "admin",
            "admin_password": "admin-password",
            "openstack_simulate": False,
            "os_auth_url": "https://keystone.example/v3",
            "os_username": "metrics-reader",
            "os_password": "reader-password",
            "os_project_id": "project-uuid",
        }
        base.update(overrides)
        return Settings(**base)

    def test_real_lookup_requires_password_credentials_and_network(self) -> None:
        with self.assertRaises(ValidationError) as raised:
            Settings(
                _env_file=None,
                jwt_secret="x" * 32,
                admin_username="admin",
                admin_password="admin-password",
                openstack_simulate=False,
            )

        message = str(raised.exception)
        self.assertIn("OS_AUTH_URL", message)
        self.assertIn("OS_PASSWORD", message)
        self.assertIn("OS_PROJECT_ID", message)

    def test_real_lookup_requires_a_user_name_or_a_user_id(self) -> None:
        with self.assertRaises(ValidationError) as raised:
            self._settings(os_username="")

        self.assertIn("OS_USER_ID or OS_USERNAME", str(raised.exception))

    def test_a_user_name_without_a_domain_is_rejected(self) -> None:
        with self.assertRaises(ValidationError) as raised:
            self._settings(os_user_domain_id="")

        self.assertIn("OS_USER_DOMAIN_ID", str(raised.exception))

    def test_a_user_id_needs_no_domain(self) -> None:
        settings = self._settings(
            os_username="", os_user_id="user-uuid", os_user_domain_id=""
        )

        self.assertEqual(settings.os_user_id, "user-uuid")

    @patch("app.services.openstack.sdk.openstack")
    def test_factory_builds_a_password_connection(self, sdk: Mock) -> None:
        settings = self._settings(
            openstack_api_timeout_seconds=12.5,
            os_user_domain_id="default",
            os_region_name="RegionOne",
            os_interface="internal",
            os_cacert="/var/run/secrets/openstack/ca.crt",
        )

        lookup = build_sdk_lookup(settings)
        lookup.close()

        sdk.connect.assert_called_once_with(
            app_name="snmp-metrics-api",
            app_version="0.7.0",
            load_yaml_config=False,
            load_envvars=False,
            auth_url="https://keystone.example/v3",
            username="metrics-reader",
            password="reader-password",
            project_id="project-uuid",
            user_domain_id="default",
            region_name="RegionOne",
            interface="internal",
            cacert="/var/run/secrets/openstack/ca.crt",
            api_timeout=12.5,
            compute_api_version="2",
            compute_default_microversion="2.47",
        )
        sdk.connect.return_value.close.assert_called_once_with()

    @patch("app.services.openstack.sdk.openstack")
    def test_a_user_id_replaces_the_name_and_domain(self, sdk: Mock) -> None:
        settings = self._settings(os_username="", os_user_id="user-uuid")

        build_sdk_lookup(settings)

        credentials = sdk.connect.call_args.kwargs
        self.assertEqual(credentials["user_id"], "user-uuid")
        self.assertNotIn("username", credentials)
        self.assertNotIn("user_domain_id", credentials)

    @patch("app.services.openstack.sdk.build_sdk_lookup")
    def test_lookup_factory_selects_real_adapter(self, sdk_factory: Mock) -> None:
        settings = self._settings()

        lookup = build_lookup(settings)

        self.assertIsInstance(lookup, CachedOpenStack)
        sdk_factory.assert_called_once_with(settings)
