# Wazuh API Script

This Python script interacts with the Wazuh API to retrieve various information about agents and API status. It supports authentication, fetching agent summaries, overviews, API information, and listing agents.

## Requirements

- Python 3.x
- `requests` library (can be installed via `pip install requests`)

## Usage

1. **Clone the repository or download the script**.
2. **Make the script executable** (optional):
    
    ```bash
    chmod +x script.py
    ```
    
3. **Run the script** with the following command:
    
    ```bash
    python script.py [options]
    ```
    

### Options

- `s`, `-summary`: Get agent summary (default output).
- `o`, `-overview`: Get agent overview.
- `a`, `-api-info`: Get API information.
- `g`, `-agents`: Get a list of agents.
- `f`, `-full-output`: Display full JSON output for summary.

### Examples

- To get the agent summary:
    
    ```bash
    python script.py --summary
    ```
    
- To get the agent overview:
    
    ```bash
    python script.py --overview
    ```
    
- To fetch API information:
    
    ```bash
    python script.py --api-info
    ```
    
- To list agents:
    
    ```bash
    python script.py --agents
    ```
    
- To get a detailed agent summary:
    
    ```bash
    python script.py --summary --full-output
    ```
    

## Configuration

Before running the script, make sure to update the following variables in the script with your Wazuh server details:

- `host`: Wazuh server IP address
- `port`: Wazuh server port
- `user`: Username for Wazuh API
- `password`: Password for Wazuh API

##
