"""
Metadata utilities for the Aptos Python SDK.

This module provides utilities for managing SDK metadata, version information,
and HTTP headers used in API requests to Aptos nodes and services. It ensures
proper identification of the Python SDK in network communications.

Key Features:
- **Version Detection**: Automatic SDK version detection from package metadata
- **HTTP Headers**: Standard headers for Aptos REST API identification
- **User-Agent**: Proper client identification for analytics and debugging
- **Compliance**: Follows Aptos API client identification standards

Use Cases:
- REST API client identification
- SDK version reporting and analytics
- Debugging and troubleshooting support
- API rate limiting and client tracking
- User-Agent construction for HTTP requests

Examples:
    Get SDK version header::
    
        from aptos_sdk.metadata import Metadata
        
        # Get the header value for HTTP requests
        header_value = Metadata.get_aptos_header_val()
        print(f"Client identifier: {header_value}")
        # Output: "aptos-python-sdk/1.2.3"
        
    Use in HTTP requests::
    
        import httpx
        from aptos_sdk.metadata import Metadata
        
        # Add SDK identification to HTTP headers
        headers = {
            Metadata.APTOS_HEADER: Metadata.get_aptos_header_val(),
            "Content-Type": "application/json"
        }
        
        # Make request with proper identification
        response = httpx.get(
            "https://fullnode.devnet.aptoslabs.com/v1",
            headers=headers
        )
        
    Integration with REST clients::
    
        # The RestClient automatically includes this header
        from aptos_sdk.async_client import RestClient
        
        client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
        # Automatically includes x-aptos-client header

Note:
    Version information is automatically detected from the installed package
    metadata. If the package is installed in development mode, it may show
    a development version identifier.
"""

import importlib.metadata as metadata

# Package name constant for metadata lookup
PACKAGE_NAME = "aptos-sdk"


class Metadata:
    """Utility class for managing Aptos SDK metadata and HTTP headers.
    
    This class provides static methods and constants for SDK identification
    in HTTP requests to Aptos services. It ensures proper client identification
    for analytics, debugging, and API compliance purposes.
    
    Constants:
        APTOS_HEADER: The standard HTTP header name for Aptos client identification
        
    Examples:
        Access header constants::
        
            from aptos_sdk.metadata import Metadata
            
            # Get the header name
            header_name = Metadata.APTOS_HEADER
            print(f"Header name: {header_name}")
            # Output: "x-aptos-client"
            
        Generate header values::
        
            # Get the full header value with version
            header_value = Metadata.get_aptos_header_val()
            print(f"Header value: {header_value}")
            # Output: "aptos-python-sdk/1.2.3"
            
        Use in custom HTTP clients::
        
            import requests
            
            headers = {
                Metadata.APTOS_HEADER: Metadata.get_aptos_header_val()
            }
            
            response = requests.get(
                "https://fullnode.mainnet.aptoslabs.com/v1",
                headers=headers
            )
    
    Note:
        The metadata class is designed to be used statically and does not
        require instantiation.
    """
    
    # HTTP header name for Aptos client identification
    APTOS_HEADER = "x-aptos-client"

    @staticmethod
    def get_aptos_header_val():
        """Generate the Aptos client header value for HTTP requests.

        This method constructs a standardized client identification string
        that includes the SDK name and version. This header is automatically
        included in requests made by the Aptos REST clients.
        
        The header format follows the pattern: "aptos-python-sdk/{version}"
        where version is automatically detected from the installed package.

        Returns:
            str: Header value in the format "aptos-python-sdk/{version}"
            
        Examples:
            Get version header::
            
                >>> from aptos_sdk.metadata import Metadata
                >>> header = Metadata.get_aptos_header_val()
                >>> print(header)
                'aptos-python-sdk/1.2.3'
                
            Use in HTTP request::
            
                import httpx
                
                headers = {
                    "x-aptos-client": Metadata.get_aptos_header_val(),
                    "Content-Type": "application/json"
                }
                
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        "https://fullnode.devnet.aptoslabs.com/v1",
                        headers=headers
                    )
                    
        Raises:
            PackageNotFoundError: If the aptos-sdk package is not properly installed
                or metadata cannot be accessed.
                
        Note:
            - Version is automatically detected from package installation
            - Development installations may show version as "0.0.0" or similar
            - This header is used by Aptos services for analytics and debugging
            - The header helps identify Python SDK traffic in server logs
        """
        version = metadata.version(PACKAGE_NAME)
        return f"aptos-python-sdk/{version}"
