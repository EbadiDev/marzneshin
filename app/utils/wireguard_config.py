from typing import List
from importlib import resources
from v2share.base import BaseConfig
from v2share.data import V2Data
from .wireguard_url import generate_wireguard_url

class WireGuardURLConfig(BaseConfig):
    """
    Custom WireGuard URL configuration class that generates WireGuard URLs
    instead of full configuration files.
    """
    
    def __init__(self, template_path=None):
        """Initialize the WireGuard URL configuration generator."""
        super().__init__()
        self.configs = []
        self.chaining_support = False
    
    def add_proxy(self, config: V2Data):
        """Add a proxy configuration to the list of proxies."""
        if config.protocol == "wireguard":
            self.configs.append(config)
    
    def add_proxies(self, configs: List[V2Data]):
        """Add multiple proxy configurations to the list of proxies."""
        for config in configs:
            self.add_proxy(config)
    
    def render(self, sort=False, shuffle=False) -> str:
        """
        Render the WireGuard URL configurations.
        Each configuration is rendered as a separate line.
        """
        if not self.configs:
            return ""
        
        if sort:
            self.configs.sort(key=lambda x: x.remark)
        
        if shuffle:
            import random
            random.shuffle(self.configs)
        
        urls = []
        for config in self.configs:
            if config.protocol != "wireguard":
                continue
                
            # Extract WireGuard-specific parameters
            private_key = config.password
            server_address = config.address
            server_port = config.port
            server_public_key = config.path  # Server public key is stored in path field
            client_address = config.client_address
            mtu = config.mtu
            allowed_ips = config.allowed_ips
            dns_servers = config.dns_servers
            remark = config.remark
            
            # Generate WireGuard URL
            url = generate_wireguard_url(
                private_key=private_key,
                server_address=server_address,
                server_port=server_port,
                client_address=client_address,
                server_public_key=server_public_key,
                allowed_ips=allowed_ips,
                mtu=mtu,
                dns_servers=dns_servers,
                remark=remark
            )
            
            urls.append(url)
        
        return "\n".join(urls) 