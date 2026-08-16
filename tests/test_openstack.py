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
            close=Mock(),
        )

        lookup = SDKOpenStack(connection, network_name="management")

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
            close=Mock(),
        )

        result = await SDKOpenStack(connection, network_name="management").servers()

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
            close=Mock(),
        )

        result = await SDKOpenStack(connection, network_name="management").servers()

        self.assertEqual(result, [])

    async def test_servers_skips_ambiguous_management_addresses(self) -> None:
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
                    },
                    {
                        "addr": "10.0.0.12",
                        "version": 4,
                        "OS-EXT-IPS:type": "fixed",
                        "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:00:00:02",
                    },
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
            close=Mock(),
        )

        result = await SDKOpenStack(connection, network_name="management").servers()

        self.assertEqual(result, [])

    def test_cache_close_releases_upstream_connection(self) -> None:
        upstream = SimpleNamespace(close=Mock())
        lookup = CachedOpenStack(upstream, ttl_seconds=300)

        lookup.close()

        upstream.close.assert_called_once_with()


class OpenStackSettingsTests(TestCase):
    def test_real_lookup_requires_application_credential_and_network(self) -> None:
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
        self.assertIn("OS_APPLICATION_CREDENTIAL_ID", message)
        self.assertIn("OS_APPLICATION_CREDENTIAL_SECRET", message)
        self.assertIn("OPENSTACK_NETWORK_NAME", message)

    @patch("app.services.openstack.sdk.Connection")
    def test_factory_builds_application_credential_connection(
        self, connection_type: Mock
    ) -> None:
        connection = connection_type.return_value
        settings = Settings(
            _env_file=None,
            jwt_secret="x" * 32,
            admin_username="admin",
            admin_password="admin-password",
            openstack_simulate=False,
            openstack_network_name="management",
            openstack_api_timeout_seconds=12.5,
            os_auth_url="https://keystone.example/v3",
            os_application_credential_id="credential-id",
            os_application_credential_secret="credential-secret",
            os_region_name="RegionOne",
            os_interface="internal",
            os_cacert="/var/run/secrets/openstack/ca.crt",
        )

        lookup = build_sdk_lookup(settings)
        lookup.close()

        connection_type.assert_called_once_with(
            app_name="snmp-metrics-api",
            app_version="0.7.0",
            auth_type="v3applicationcredential",
            auth={
                "auth_url": "https://keystone.example/v3",
                "application_credential_id": "credential-id",
                "application_credential_secret": "credential-secret",
            },
            region_name="RegionOne",
            interface="internal",
            cacert="/var/run/secrets/openstack/ca.crt",
            api_timeout=12.5,
            compute_api_version="2",
            compute_default_microversion="2.47",
        )
        connection.close.assert_called_once_with()

    @patch("app.services.openstack.sdk.build_sdk_lookup")
    def test_lookup_factory_selects_real_adapter(self, sdk_factory: Mock) -> None:
        settings = Settings(
            _env_file=None,
            jwt_secret="x" * 32,
            admin_username="admin",
            admin_password="admin-password",
            openstack_simulate=False,
            openstack_network_name="management",
            os_auth_url="https://keystone.example/v3",
            os_application_credential_id="credential-id",
            os_application_credential_secret="credential-secret",
        )

        lookup = build_lookup(settings)

        self.assertIsInstance(lookup, CachedOpenStack)
        sdk_factory.assert_called_once_with(settings)
