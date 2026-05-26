import json
import argparse
import copy
import sys
import os

class Router:
    def __init__(self, ip):
        self.ip = ip
        self.table = {}
        self.table[self.ip] = {"next_hop": self.ip, "metric": 0}
        self.neighbors = []

    def add_neighbor(self, neighbor_ip):
        if neighbor_ip not in self.neighbors:

            self.neighbors.append(neighbor_ip)
            self.table[neighbor_ip] = {"next_hop": neighbor_ip, "metric": 1}

def load_network(filepath):
    if not os.path.exists(filepath):
        print(f"Ошибка: Файл {filepath} не найден.")
        sys.exit(1)
        
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    routers = {}

    for r_data in data.get("routers", []):
        ip = r_data["ip"]
        routers[ip] = Router(ip)

    for link in data.get("links", []):
        ip1 = link[0]
        ip2 = link[1]

        if ip1 not in routers: routers[ip1] = Router(ip1)
        if ip2 not in routers: routers[ip2] = Router(ip2)

        routers[ip1].add_neighbor(ip2)
        routers[ip2].add_neighbor(ip1)
        
    return routers

def simulate_rip(routers):
    changed = True
    iterations = 0
    max_iterations = 16

    while changed and iterations < max_iterations:
        changed = False
        
        last_copy = copy.deepcopy(routers)

        for ip, router in routers.items():
            for neighbor_ip in router.neighbors:
                neighbor_table = last_copy[neighbor_ip].table
                
                for dest_ip, entry in neighbor_table.items():
                    new_metric = entry['metric'] + 1
                    
                    if dest_ip not in router.table or new_metric < router.table[dest_ip]['metric']:
                        router.table[dest_ip] = {"next_hop": neighbor_ip, "metric": new_metric}
                        changed = True
        iterations += 1

def print_routing_tables(routers):
    for ip, router in routers.items():
        print(f"Final state of router {ip} table:")
        print(f"{'[Source IP]':<18} {'[Destination IP]':<18} {'[Next Hop]':<18} {'[Metric]'}")
        
        for dest_ip, entry in router.table.items():
            if dest_ip == ip: 
                continue
            print(f"{ip:<18} {dest_ip:<18} {entry['next_hop']:<18} {entry['metric']:>8}")

        print("-" * 65)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Реализация эмулятора протокола RIP")
    parser.add_argument("-c", "--config", type=str, default="config.json", help="Путь к файлу конфигурации JSON")
    args = parser.parse_args()

    network_routers = load_network(args.config)
    simulate_rip(network_routers)
    print_routing_tables(network_routers)