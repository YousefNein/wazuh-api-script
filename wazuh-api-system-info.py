#!/usr/bin/env python3

import json
import requests
import urllib3
from base64 import b64encode
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

protocol = 'https'
host = '10.10.50.3'
port = 55000
user = 'wazuh-wui'
password = 'JXibl6UhHT4wZf7fdXF+64PCe36zyOqw'
login_endpoint = 'security/user/authenticate'

def authenticate():
    """Authenticate and get the token."""
    try:
        login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
        basic_auth = f"{user}:{password}".encode()
        login_headers = {'Content-Type': 'application/json',
                         'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
        response = requests.post(login_url, headers=login_headers, verify=False)
        response.raise_for_status()
        return json.loads(response.content.decode())['data']['token']
    except requests.RequestException as e:
        print(f"Error during authentication: {e}")
        return None

def get_agent_summary(token, full_output=False):
    """Fetch agent summary."""
    try:
        requests_headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        agent_summary_response = requests.get(f"{protocol}://{host}:{port}/agents/summary/status?pretty=true",
                                              headers=requests_headers, verify=False)
        agent_summary_response.raise_for_status()
        agent_summary_data = agent_summary_response.json()

        if full_output:
            print(json.dumps(agent_summary_data, indent=4))
        else:
            connection = agent_summary_data.get("data", {}).get("connection", {})
            print(f"Active agents: {connection.get('active')}")
            print(f"Disconnected agents: {connection.get('disconnected')}")
            print(f"Total agents: {connection.get('total')}")
    except requests.RequestException as e:
        print(f"Error fetching agent summary: {e}")
        print(agent_summary_data)

def get_agent_overview(token, full_output=False):
    """Fetch agent overview with parsed details."""
    try:
        requests_headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        agent_overview_response = requests.get(f"{protocol}://{host}:{port}/overview/agents", 
                                               headers=requests_headers, verify=False)
        agent_overview_response.raise_for_status()
        agent_overview_data = agent_overview_response.json()

        if full_output:
            print(json.dumps(agent_overview_data, indent=4))
        else:
            # Extract node details
            nodes = agent_overview_data.get('data', {}).get('nodes', [])
            if nodes:
                for node in nodes:
                    print(f"Node Name: {node.get('node_name')}, Node Count: {node.get('count')}")
            else:
                print("No nodes found.")

            # Extract group details
            groups = agent_overview_data.get('data', {}).get('groups', [])
            if groups:
                group_names = [group.get('name') for group in groups]
                print(f"Groups: {', '.join(group_names)}")
            else:
                print("No groups found.")

            # Extract agent OS details
            agent_os = agent_overview_data.get('data', {}).get('agent_os', [])
            if agent_os:
                for os_entry in agent_os:
                    os_info = os_entry.get('os', {})
                    os_name = os_info.get('name', 'Unknown OS')
                    os_version = os_info.get('version', 'Unknown Version')
                    print(f"Agent OS: {os_name}, Version: {os_version}, Count: {os_entry.get('count')}")
            else:
                print("No agent OS found.")

            # Extract last registered agent details
            last_registered_agent = agent_overview_data.get('data', {}).get('last_registered_agent', [])
            if last_registered_agent:
                agent = last_registered_agent[0]  # Assuming we're only displaying the most recent one
                agent_name = agent.get('name', 'Unknown Agent')
                agent_os = agent.get('os', {}).get('name', 'Unknown OS')
                agent_ip = agent.get('ip', 'Unknown IP')
                last_connection = agent.get('lastKeepAlive', 'Unknown Last Connection')
                print(f"Last Registered Agent: {agent_name}")
                print(f"  OS: {agent_os}")
                print(f"  IP: {agent_ip}")
                print(f"  Last Keep Alive: {last_connection}")
            else:
                print("No last registered agent found.")
    except requests.RequestException as e:
        print(f"Error fetching agent overview: {e}")
        print(agent_overview_data)


def get_api_info(token, full_output=False):
    """Fetch API information."""
    try:
        requests_headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        api_info_response = requests.get(f"{protocol}://{host}:{port}/", headers=requests_headers, verify=False)
        api_info_response.raise_for_status()
        api_info_data = api_info_response.json()

        if full_output:
            print(json.dumps(api_info_data, indent=4))
        else:
            api_info = api_info_data.get("data", {})
            print(f"Title: {api_info.get('title')}")
            print(f"API Version: {api_info.get('api_version')}")
            print(f"Hostname: {api_info.get('hostname')}")
            print(f"Timestamp: {api_info.get('timestamp')}")
    except requests.RequestException as e:
        print(f"Error fetching API info: {e}")
        print(api_info_data)

def get_agents(token, full_output=False):
    """Fetch agents and parse details."""
    try:
        requests_headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        agents_response = requests.get(f"{protocol}://{host}:{port}/agents", headers=requests_headers, verify=False)
        agents_response.raise_for_status()
        agents_data = agents_response.json()

        if full_output:
            print(json.dumps(agents_data, indent=4))
        else:
            agents = agents_data.get("data", {}).get("affected_items", [])
            if agents:
                for agent in agents:
                    print(f"Agent Name: {agent.get('name')}")
                    print(f"  OS: {agent.get('os', {}).get('name', 'Unknown OS')} {agent.get('os', {}).get('version', '')}")
                    print(f"  Status: {agent.get('status', 'Unknown Status')}")
                    print(f"  Last Keep Alive: {agent.get('lastKeepAlive', 'Unknown Last Keep Alive')}")
                    print(f"  IP: {agent.get('ip', 'Unknown IP')}")
                    print(f"  Manager: {agent.get('manager', 'Unknown Manager')}")
                    print(f"  Node: {agent.get('node_name', 'Unknown Node')}\n")
            else:
                print("No agents found.")
    except requests.RequestException as e:
        print(f"Error fetching agents: {e}")
        print(agents_data)

def main():
    parser = argparse.ArgumentParser(description="Wazuh API Script")
    parser.add_argument('-s', '--summary', action='store_true', help='Get agent summary (default output)')
    parser.add_argument('-o', '--overview', action='store_true', help='Get agent overview')
    parser.add_argument('-a', '--api-info', action='store_true', help='Get API information')
    parser.add_argument('-g', '--agents', action='store_true', help='Get list of agents')
    parser.add_argument('-f', '--full-output', action='store_true', help='Display full JSON output for summary')

    args = parser.parse_args()

    token = authenticate()
    if not token:
        return

    if args.summary or not (args.overview or args.api_info or args.agents):
        get_agent_summary(token, args.full_output)

    if args.overview:
        get_agent_overview(token, args.full_output)

    if args.api_info:
        get_api_info(token, args.full_output)

    if args.agents:
        get_agents(token, args.full_output)

if __name__ == "__main__":
    main()
