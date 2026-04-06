"""Models for the Sagemcom F@st client."""

import dataclasses
from dataclasses import dataclass
from typing import Any


# pylint: disable=too-many-instance-attributes
@dataclass
class Device:
    """Device connected to a router."""

    uid: int | None = None
    alias: str | None = None
    phys_address: str | None = None
    ip_address: str | None = None
    address_source: str | None = None
    dhcp_client: str | None = None
    lease_time_remaining: int | None = None
    associated_device: Any | None = None
    layer1_interface: Any | None = None
    layer3_interface: Any | None = None
    vendor_class_id: Any | None = None
    client_id: Any | None = None
    user_class_id: Any | None = None
    host_name: Any | None = None
    active: bool | None = None
    lease_start: int | None = None
    lease_duration: int | None = None
    interface_type: str | None = None  # enum!
    detected_device_type: str | None = None
    active_last_change: Any | None = None
    user_friendly_name: str | None = None
    user_host_name: str | None = None
    user_device_type: Any | None = None  # enum!
    icon: Any | None = None
    room: Any | None = None
    blacklist_enable: bool | None = None
    blacklisted: bool | None = None
    unblock_hours_count: int | None = None
    blacklist_status: bool | None = None
    blacklisted_according_to_schedule: bool | None = None
    blacklisted_schedule: list | None = None
    hidden: bool | None = None
    options: list | None = None
    vendor_class_idv6: Any | None = None
    ipv4_addresses: list | None = None
    ipv6_addresses: list | None = None
    device_type_association: Any | None = None

    # pylint:disable=fixme
    # TODO Remove extra kwargs before init
    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for key, value in kwargs.items():
            if key in names:
                setattr(self, key, value)

    @property
    def id(self):
        """Return unique ID for device."""
        return self.phys_address.upper() if self.phys_address else None

    @property
    def name(self):
        """Return name of the device."""
        return self.user_host_name or self.host_name


# pylint: disable=too-many-instance-attributes
@dataclass
class DeviceInfo:
    """Sagemcom Router representation."""

    mac_address: str
    serial_number: str | None = None
    manufacturer: Any | None = None
    model_name: Any | None = None
    model_number: Any | None = None
    software_version: str | None = None
    hardware_version: str | None = None
    bootloader_version: Any | None = None
    device_category: Any | None = None
    manufacturer_oui: Any | None = None
    product_class: str | None = None
    description: str | None = None
    additional_hardware_version: str | None = None
    additional_software_version: str | None = None
    external_firmware_version: str | None = None
    internal_firmware_version: str | None = None
    gui_firmware_version: str | None = None
    guiapi_version: float | None = None
    provisioning_code: str | None = None
    up_time: int | None = None
    first_use_date: str | None = None
    mode: str | None = None
    country: str | None = None
    reboot_count: int | None = None
    nodes_to_restore: str | None = None
    router_name: str | None = None
    reboot_status: float | None = None
    reset_status: float | None = None
    update_status: float | None = None
    SNMP: bool | None = None  # pylint: disable=invalid-name
    first_connection: bool | None = None
    build_date: str | None = None
    spec_version: str | None = None
    CLID: str | None = None  # pylint: disable=invalid-name
    flush_device_log: bool | None = None
    locations: str | None = None
    api_version: str | None = None

    # pylint:disable=fixme
    # TODO Remove extra kwargs before init
    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for key, value in kwargs.items():
            if key in names:
                setattr(self, key, value)

    @property
    def id(self):
        """Return unique ID for gateway."""
        return self.mac_address


# pylint: disable=too-many-instance-attributes
@dataclass
class PortMapping:
    """Port Mapping representation."""

    uid: int
    enable: bool
    status: str | None = None  # Enum
    alias: str | None = None
    external_interface: str | None = None
    all_external_interfaces: bool | None = None
    lease_duration: int | None = None
    external_port: int | None = None
    external_port_end_range: int | None = None
    internal_interface: str | None = None
    internal_port: int | None = None
    protocol: str | None = None
    service: str | None = None
    internal_client: str | None = None
    public_ip: str | None = None
    description: str | None = None
    creator: str | None = None
    target: str | None = None
    lease_start: str | None = None  # Date?

    # pylint:disable=fixme
    # TODO Remove extra kwargs before init
    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for key, value in kwargs.items():
            if key in names:
                setattr(self, key, value)

    @property
    def id(self):
        """Return unique ID for port mapping."""
        return self.uid
