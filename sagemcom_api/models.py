"""Models for the Sagemcom F@st client."""

import dataclasses
from dataclasses import dataclass
from typing import Any, List, Optional


@dataclass
class Device:
    """Device connected to a router."""

    uid: Optional[int] = None
    alias: Optional[str] = None
    phys_address: Optional[str] = None
    ip_address: Optional[str] = None
    address_source: Optional[str] = None
    dhcp_client: Optional[str] = None
    lease_time_remaining: Optional[int] = None
    associated_device: Optional[Any] = None
    layer1_interface: Optional[Any] = None
    layer3_interface: Optional[Any] = None
    vendor_class_id: Optional[Any] = None
    client_id: Optional[Any] = None
    user_class_id: Optional[Any] = None
    host_name: Optional[Any] = None
    active: Optional[bool] = None
    lease_start: Optional[int] = None
    lease_duration: Optional[int] = None
    interface_type: Optional[str] = None  # enum!
    detected_device_type: Optional[str] = None
    active_last_change: Optional[Any] = None
    user_friendly_name: Optional[str] = None
    user_host_name: Optional[str] = None
    user_device_type: Optional[Any] = None  # enum!
    icon: Optional[Any] = None
    room: Optional[Any] = None
    blacklist_enable: Optional[bool] = None
    blacklisted: Optional[bool] = None
    unblock_hours_count: Optional[int] = None
    blacklist_status: Optional[bool] = None
    blacklisted_according_to_schedule: Optional[bool] = None
    blacklisted_schedule: Optional[List] = None
    hidden: Optional[bool] = None
    options: Optional[List] = None
    vendor_class_idv6: Optional[Any] = None
    ipv4_addresses: Optional[List] = None
    ipv6_addresses: Optional[List] = None
    device_type_association: Optional[Any] = None

    # TODO Remove extra kwargs before init
    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)

    @property
    def id(self):
        """Return unique ID for device."""
        return self.phys_address.upper()

    @property
    def name(self):
        """Return name of the device."""
        return self.user_host_name or self.host_name


@dataclass
class DeviceInfo:
    """Sagemcom Router representation."""

    mac_address: str
    serial_number: Optional[str] = None
    manufacturer: Optional[Any] = None
    model_name: Optional[Any] = None
    model_number: Optional[Any] = None
    software_version: Optional[str] = None
    hardware_version: Optional[str] = None
    up_time: Optional[Any] = None
    reboot_count: Optional[Any] = None
    router_name: Optional[Any] = None
    bootloader_version: Optional[Any] = None
    device_category: Optional[Any] = None
    manufacturer_oui: Optional[Any] = None
    product_class: Optional[str] = None
    description: Optional[str] = None
    additional_hardware_version: Optional[str] = None
    additional_software_version: Optional[str] = None
    external_firmware_version: Optional[str] = None
    internal_firmware_version: Optional[str] = None
    gui_firmware_version: Optional[str] = None
    guiapi_version: Optional[float] = None
    provisioning_code: Optional[str] = None
    up_time: Optional[int] = None
    first_use_date: Optional[str] = None
    mac_address: Optional[str] = None
    mode: Optional[str] = None
    country: Optional[str] = None
    reboot_count: Optional[int] = None
    nodes_to_restore: Optional[str] = None
    router_name: Optional[str] = None
    reboot_status: Optional[float] = None
    reset_status: Optional[float] = None
    update_status: Optional[float] = None
    SNMP: Optional[bool] = None
    first_connection: Optional[bool] = None
    build_date: Optional[str] = None
    spec_version: Optional[str] = None
    CLID: Optional[str] = None
    flush_device_log: Optional[bool] = None
    locations: Optional[str] = None
    api_version: Optional[str] = None

    # TODO Remove extra kwargs before init
    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)

    @property
    def id(self):
        """Return unique ID for gateway."""
        return self.mac_address


@dataclass
class PortMapping:
    """Port Mapping representation."""

    uid: int
    enable: bool
    status: Optional[str] = None  # Enum
    alias: Optional[str] = None
    external_interface: Optional[str] = None
    all_external_interfaces: Optional[bool] = None
    lease_duration: Optional[int] = None
    external_port: Optional[int] = None
    external_port_end_range: Optional[int] = None
    internal_interface: Optional[str] = None
    internal_port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    internal_client: Optional[str] = None
    public_ip: Optional[str] = None
    description: Optional[str] = None
    creator: Optional[str] = None
    target: Optional[str] = None
    lease_start: Optional[str] = None  # Date?

    # TODO Remove extra kwargs before init
    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)

    @property
    def id(self):
        """Return unique ID for port mapping."""
        return self.uid
