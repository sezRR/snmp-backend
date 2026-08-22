from unittest import TestCase

from app.db.metrics import METRIC_COLUMNS
from app.services.snmp.flatten import COLUMNS, flatten, nest

VIRTUAL = ("veth", "cni", "flannel", "docker", "br-", "tailscale")
PSEUDO = ("/run", "/dev/shm", "/sys", "/proc", "/snap")

# The payload documented in the README, trimmed to one of each entity.
README_PAYLOAD = {
    "cpu": {"usage_percent": 22.93, "cores": 1},
    "ram": {
        "total_bytes": 2147483648,
        "used_bytes": 727130208,
        "used_percent": 33.86,
        "available_bytes": 1420353440,
        "buffers_bytes": 35889152,
        "cached_bytes": 1121976320,
    },
    "disk": [
        {
            "mount": "/",
            "total_bytes": 21474836480,
            "used_bytes": 8967258924,
            "used_percent": 41.76,
        }
    ],
    "disk_io": {
        "read_bps": 112487038.9,
        "write_bps": 45507872.5,
        "read_iops": 6865.7,
        "write_iops": 11110.3,
        "read_bytes": 1450273321378,
        "write_bytes": 1853005660426,
        "reads": 173272109,
        "writes": 193994381,
        "interval_seconds": 4.998,
        "devices": [
            {
                "device": "vda",
                "read_bps": 112487038.9,
                "write_bps": 45507872.5,
                "busy_percent_1min": 30.14,
                "counted": True,
            }
        ],
    },
    "network": {
        "rx_bps": 812344.5,
        "tx_bps": 1904771.2,
        "rx_bytes": 402653184000,
        "tx_bytes": 915678412000,
        "interval_seconds": 5.02,
        "interfaces": [
            {
                "name": "eth0",
                "rx_bps": 812344.5,
                "tx_bps": 1904771.2,
                "rx_bytes": 402653184000,
                "tx_bytes": 915678412000,
                "speed_bps": 1000000000,
                "rx_util_percent": 0.65,
                "tx_util_percent": 1.52,
            }
        ],
    },
}


def _flatten(payload):
    return flatten(
        payload, pseudo_mount_prefixes=PSEUDO, virtual_iface_prefixes=VIRTUAL
    )


class ColumnListTests(TestCase):
    def test_flatten_covers_exactly_the_table(self) -> None:
        """The mapping and the schema cannot drift apart silently.

        `flatten` names its columns by hand; `METRIC_COLUMNS` reads them off the
        SQLAlchemy table. A column added to one and not the other is either an
        insert that fails or a column that is never written.
        """
        self.assertEqual(COLUMNS, METRIC_COLUMNS)

    def test_every_column_is_present_even_for_an_empty_payload(self) -> None:
        row = _flatten({})
        self.assertEqual(set(row), set(COLUMNS))
        self.assertTrue(all(value is None for value in row.values()))


class FlattenTests(TestCase):
    def test_readme_payload(self) -> None:
        row = _flatten(README_PAYLOAD)
        self.assertEqual(row["cpu_usage_pct"], 22.93)
        self.assertEqual(row["cpu_cores"], 1)
        self.assertEqual(row["ram_used_pct"], 33.86)
        self.assertEqual(row["disk_root_used_pct"], 41.76)
        self.assertEqual(row["disk_max_used_pct"], 41.76)
        self.assertEqual(row["dio_busy_pct"], 30.14)
        self.assertEqual(row["net_rx_bps"], 812344.5)
        self.assertEqual(row["net_speed_bps"], 1000000000)
        # Both sections report the same window; one column holds it.
        self.assertEqual(row["interval_ms"], 4998)

    def test_missing_network_section(self) -> None:
        """An IF-MIB walk that failed leaves `network` empty, not absent."""
        payload = dict(README_PAYLOAD, network={})
        row = _flatten(payload)
        self.assertIsNone(row["net_rx_bps"])
        self.assertIsNone(row["net_speed_bps"])
        # The rest of the sample still lands.
        self.assertEqual(row["cpu_usage_pct"], 22.93)

    def test_missing_disk_io_section(self) -> None:
        """An agent with no DISKIO-MIB omits the key entirely."""
        payload = {k: v for k, v in README_PAYLOAD.items() if k != "disk_io"}
        row = _flatten(payload)
        self.assertIsNone(row["dio_read_bps"])
        self.assertIsNone(row["dio_busy_pct"])
        # interval_seconds then has to come from the network section.
        self.assertEqual(row["interval_ms"], 5020)

    def test_rates_are_none_not_zero_on_the_first_sample(self) -> None:
        """A rate needs two counter readings. None, so averages skip it."""
        payload = dict(
            README_PAYLOAD,
            network={
                "interfaces": [
                    {"name": "eth0", "rx_bps": None, "tx_bps": None, "rx_bytes": 7}
                ]
            },
        )
        row = _flatten(payload)
        self.assertIsNone(row["net_rx_bps"])
        self.assertEqual(row["net_rx_bytes"], 7)


class VirtualInterfaceTests(TestCase):
    def test_virtual_interfaces_do_not_count_toward_the_total(self) -> None:
        """The bug this schema change fixes.

        A packet leaving a pod crosses the veth, the bridge and the uplink, and
        the old total added all three. Only the uplink moved it off the machine.
        """
        payload = {
            "network": {
                "interfaces": [
                    {"name": "eth0", "rx_bps": 100.0, "rx_bytes": 1000},
                    {"name": "cni0", "rx_bps": 60.0, "rx_bytes": 600},
                    {"name": "vethab3ec5c3", "rx_bps": 30.0, "rx_bytes": 300},
                    {"name": "flannel.1", "rx_bps": 10.0, "rx_bytes": 100},
                    {"name": "tailscale0", "rx_bps": 25.0, "rx_bytes": 250},
                ]
            }
        }
        row = _flatten(payload)
        self.assertEqual(row["net_rx_bps"], 100.0)
        self.assertEqual(row["net_rx_bytes"], 1000)

    def test_rates_and_counters_use_the_same_interface_set(self) -> None:
        """The old payload summed rated interfaces for bps and every interface
        for bytes, so the two disagreed about which machine they described."""
        payload = {
            "network": {
                "interfaces": [
                    {"name": "eth0", "rx_bps": 100.0, "rx_bytes": 1000},
                    {"name": "eth1", "rx_bps": None, "rx_bytes": 500},
                    {"name": "veth0", "rx_bps": 999.0, "rx_bytes": 9999},
                ]
            }
        }
        row = _flatten(payload)
        # eth1 wrapped its counter this tick, so it has no rate to add - but it
        # is still one of the machine's physical interfaces.
        self.assertEqual(row["net_rx_bps"], 100.0)
        self.assertEqual(row["net_rx_bytes"], 1500)

    def test_utilisation_and_speed_take_the_busiest_physical_link(self) -> None:
        payload = {
            "network": {
                "interfaces": [
                    {"name": "eth0", "speed_bps": 1_000_000_000, "rx_util_percent": 4.0},
                    {"name": "veth0", "speed_bps": 10_000_000_000, "rx_util_percent": 90.0},
                ]
            }
        }
        row = _flatten(payload)
        self.assertEqual(row["net_speed_bps"], 1_000_000_000)
        self.assertEqual(row["net_rx_util_pct"], 4.0)


class DiskTests(TestCase):
    def test_pseudo_mounts_do_not_set_the_maximum(self) -> None:
        """A full tmpfs is a tmpfs doing its job, not a disk about to fill."""
        payload = {
            "disk": [
                {"mount": "/", "used_percent": 57.67, "used_bytes": 1, "total_bytes": 2},
                {"mount": "/run/credentials/getty@tty1.service", "used_percent": 100.0},
                {"mount": "/dev/shm", "used_percent": 99.0},
                {"mount": "/var", "used_percent": 81.0},
            ]
        }
        row = _flatten(payload)
        self.assertEqual(row["disk_root_used_pct"], 57.67)
        # /var is a real filesystem and is fuller than root, which is exactly
        # the case root-only storage would have hidden.
        self.assertEqual(row["disk_max_used_pct"], 81.0)

    def test_a_machine_with_no_root_row_reports_none(self) -> None:
        row = _flatten({"disk": [{"mount": "/data", "used_percent": 12.0}]})
        self.assertIsNone(row["disk_root_used_pct"])
        self.assertEqual(row["disk_max_used_pct"], 12.0)

    def test_every_mount_filtered_falls_back_to_all_of_them(self) -> None:
        """A host whose mounts all look pseudo is likelier to be one this list
        does not describe than one with no disks at all."""
        row = _flatten({"disk": [{"mount": "/run/x", "used_percent": 4.0}]})
        self.assertEqual(row["disk_max_used_pct"], 4.0)

    def test_uncounted_devices_do_not_set_busy_percent(self) -> None:
        """`counted` is false for loop, ram and partition devices, which the
        kernel reports alongside the disk underneath them."""
        payload = {
            "disk_io": {
                "devices": [
                    {"device": "loop0", "busy_percent_1min": 99.0, "counted": False},
                    {"device": "sda", "busy_percent_1min": 12.0, "counted": True},
                ]
            }
        }
        self.assertEqual(_flatten(payload)["dio_busy_pct"], 12.0)

    def test_counted_flag_is_not_read_as_a_number(self) -> None:
        """`True` is an `int` in Python and would otherwise store as 1."""
        row = _flatten({"cpu": {"cores": True}})
        self.assertIsNone(row["cpu_cores"])


class NestTests(TestCase):
    def test_round_trip(self) -> None:
        """`nest` is the exact inverse of `flatten` for a stored row.

        This is what lets `GET /metrics` keep serving the nested shape clients
        have always read, without storing it.
        """
        stored = _flatten(README_PAYLOAD)
        self.assertEqual(_flatten(nest(stored)), stored)

    def test_disk_comes_back_as_root_alone(self) -> None:
        payload = nest(_flatten(README_PAYLOAD))
        self.assertEqual([d["mount"] for d in payload["disk"]], ["/"])

    def test_per_entity_keys_are_absent_rather_than_empty(self) -> None:
        """An empty array asserts the machine has no interfaces, which is a
        different claim from not having stored them."""
        payload = nest(_flatten(README_PAYLOAD))
        self.assertNotIn("interfaces", payload["network"])
        self.assertNotIn("devices", payload["disk_io"])

    def test_a_section_with_nothing_in_it_is_empty(self) -> None:
        payload = nest(_flatten({"cpu": {"usage_percent": 1.0}}))
        self.assertEqual(payload["network"], {})
        self.assertNotIn("disk_io", payload)
        self.assertEqual(payload["disk"], [])
