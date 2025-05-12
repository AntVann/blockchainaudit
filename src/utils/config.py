"""
Configuration utilities for the blockchain audit system.
"""
import os
import yaml
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_config(config_file_path=None):
    """
    Load configuration from a YAML file.
    
    Args:
        config_file_path: Path to the configuration file. If None, will try to load
                        from the default location.
    
    Returns:
        dict: Configuration dictionary
    
    Raises:
        FileNotFoundError: If the config file is not found
        yaml.YAMLError: If the config file is not valid YAML
    """
    # Use default config path if none provided
    if config_file_path is None:
        # Try to find config in project root directory
        project_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        config_file_path = os.path.join(project_dir, 'config.yaml')
    
    logger.info(f"Loading configuration from {config_file_path}")
    
    try:
        with open(config_file_path, 'r') as file:
            config = yaml.safe_load(file)
        
        logger.info(f"Configuration loaded successfully")
        return config
    
    except FileNotFoundError:
        logger.error(f"Configuration file not found at {config_file_path}")
        raise
    
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration: {str(e)}")
        raise
    
    except Exception as e:
        logger.error(f"Unexpected error loading configuration: {str(e)}")
        raise

def get_peer_addresses(config=None):
    """
    Get peer addresses from configuration.
    
    Args:
        config: Configuration dictionary. If None, will load from default location.
        
    Returns:
        list: List of peer addresses
    """
    if config is None:
        config = load_config()
    
    try:
        peers = config.get('peers', [])
        # Extract addresses from peer items
        addresses = [peer['address'] for peer in peers if 'address' in peer]
        logger.info(f"Loaded {len(addresses)} peer addresses from configuration")
        return addresses
    
    except KeyError as e:
        logger.error(f"Missing key in configuration: {str(e)}")
        return []
    
    except Exception as e:
        logger.error(f"Error extracting peer addresses from configuration: {str(e)}")
        return []

def get_server_config(config=None):
    """
    Get server configuration.
    
    Args:
        config: Configuration dictionary. If None, will load from default location.
        
    Returns:
        dict: Server configuration dictionary with defaults applied
    """
    if config is None:
        config = load_config()
    
    # Get server configuration with defaults
    server_config = config.get('server', {})
    
    # Apply defaults if not present
    defaults = {
        'heartbeat_interval': 5,
        'max_workers': 10
    }
    
    for key, default_value in defaults.items():
        if key not in server_config:
            server_config[key] = default_value
            
    return server_config
