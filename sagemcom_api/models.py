from collections import namedtuple
from enum import Enum

class EncryptionMethod(Enum):
    def __str__(self):
        return str(self.value)

    MD5 = 'md5'
    SHA512 = 'sha512'
    UNKNOWN = 'unknown'

DeviceInfo = namedtuple(
    "DeviceInfo", [
        "mac_address",
        "serial_number",
        "manufacturer",
        "model_name",
        "model_number",
        "software_version",
        "hardware_version",
        "uptime",
        "reboot_count",
        "router_name",
        "bootloader_version"
    ])

Device = namedtuple(
    "Device", [
        "mac_address",
        "ip_address",
        "ipv4_addresses",
        "ipv6_addresses",
        "name",
        "address_source",
        "interface",
        "active",
        "user_friendly_name",
        "detected_device_type",
        "user_device_type"
    ])
