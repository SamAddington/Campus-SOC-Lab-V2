from typing import Dict, Type

from .base import LMSProvider, SyncResult
from .canvas import CanvasProvider
from .blackboard import BlackboardProvider
from .moodle import MoodleProvider
from .brightspace import BrightspaceProvider
from .meraki import MerakiProvider
from .duo import DuoProvider
from .umbrella import UmbrellaProvider
from .ise import ISEProvider
from .firepower import FirepowerProvider
from .restconf import RESTCONFProvider
from .snmp import SNMPProvider
from .netconf import NETCONFProvider
from .ssh_poll import SSHPollProvider

__all__ = [
    "LMSProvider",
    "SyncResult",
    "CanvasProvider",
    "BlackboardProvider",
    "MoodleProvider",
    "BrightspaceProvider",
    "MerakiProvider",
    "DuoProvider",
    "UmbrellaProvider",
    "ISEProvider",
    "FirepowerProvider",
    "RESTCONFProvider",
    "SNMPProvider",
    "NETCONFProvider",
    "SSHPollProvider",
    "PROVIDER_REGISTRY",
]

PROVIDER_REGISTRY: Dict[str, Type[LMSProvider]] = {
    "canvas": CanvasProvider,
    "blackboard": BlackboardProvider,
    "moodle": MoodleProvider,
    "brightspace": BrightspaceProvider,
    "meraki": MerakiProvider,
    "duo": DuoProvider,
    "umbrella": UmbrellaProvider,
    "ise": ISEProvider,
    "firepower": FirepowerProvider,
    "restconf": RESTCONFProvider,
    "snmp": SNMPProvider,
    "netconf": NETCONFProvider,
    "ssh_poll": SSHPollProvider,
}
