import urllib.parse
from typing import Optional, List

def generate_wireguard_url(
    private_key: str,
    server_address: str,
    server_port: int,
    client_address: str,
    server_public_key: str,
    allowed_ips: Optional[List[str]] = None,
    mtu: Optional[int] = 1420,
    dns_servers: Optional[List[str]] = None,
    preshared_key: Optional[str] = None,
    reserved: Optional[str] = None,
    remark: Optional[str] = None
) -> str:
    """
    Generate a WireGuard URL in the format:
    wireguard://private_key@server:port?param=value&param2=value2#remark
    
    This follows a similar format to the Hysteria2 URL scheme.
    """
    # Base URL format
    url = f"wireguard://{private_key}@{server_address}:{server_port}"
    
    # Query parameters
    params = {}
    
    # Add required parameters
    params['address'] = client_address
    params['publickey'] = server_public_key
    
    # Add optional parameters if provided
    if mtu:
        params['mtu'] = str(mtu)
    
    if allowed_ips:
        params['allowed_ips'] = ','.join(allowed_ips)
    
    if dns_servers:
        params['dns'] = ','.join(dns_servers)
    
    if preshared_key:
        params['presharedkey'] = preshared_key
    
    if reserved:
        params['reserved'] = reserved
    
    # Build query string
    query_string = '&'.join([f"{key}={urllib.parse.quote(value)}" for key, value in params.items()])
    
    # Complete URL with query parameters
    complete_url = f"{url}?{query_string}"
    
    # Add remark/tag if provided
    if remark:
        complete_url = f"{complete_url}#{urllib.parse.quote(remark)}"
    
    return complete_url 