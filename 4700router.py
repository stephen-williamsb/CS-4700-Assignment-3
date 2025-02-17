#!/usr/bin/env -S python3 -u

import argparse, socket, time, json, select, sys

def ip_to_tuple(ip):
    """Convert an IP address string to a tuple of integers for easy comparison."""
    return tuple(int(part) for part in ip.split('.'))

def ip_str_to_int(ip):
    """Convert an IP address string to a 32-bit integer."""
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

def prefix_mask(prefix_len):
    """Return a 32-bit mask for the given prefix length."""
    return (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF

def netmask_to_prefix(netmask):
    """
    Convert a netmask to a prefix length.
    If the netmask contains a dot, it is assumed to be in dotted-decimal format.
    Otherwise, it is assumed to be the prefix length.
    """
    if '.' in netmask:
        m_int = ip_str_to_int(netmask)
        prefix = 0
        # Count the number of 1-bits from the left
        for i in range(32):
            if m_int & (1 << (31 - i)):
                prefix += 1
            else:
                break
        return prefix
    else:
        return int(netmask)

def ip_in_network(ip, network, prefix_len):
    """Check if an IP address (string) is in the given network (string) with prefix length."""
    ip_int = ip_str_to_int(ip)
    network_int = ip_str_to_int(network)
    mask = prefix_mask(prefix_len)
    return (ip_int & mask) == (network_int & mask)

class Router:
    def __init__(self, asn, connections):
        print("Router at AS %s starting up" % asn)
        self.asn = asn
        self.relations = {}  # Neighbor relationship type (peer/provider/customer)
        self.sockets = {}  # UDP sockets for each neighbor
        self.ports = {}  # Port numbers for each neighbor
        self.updates = []  # Store all received updates
        self.withdraws = []  # Store all received withdraws
        self.forwarding_table = []  # Current routing table

        # Initialize connections
        for relationship in connections:
            port, neighbor, relation = relationship.split("-")
            self.sockets[neighbor] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sockets[neighbor].bind(('localhost', 0))
            self.ports[neighbor] = int(port)
            self.relations[neighbor] = relation

            # Send initial handshake
            self.send(neighbor, json.dumps({
                "type": "handshake",
                "src": self.our_addr(neighbor),
                "dst": neighbor,
                "msg": {}
            }))

    def our_addr(self, dst):
        # Get our address on the interface to a neighbor
        quads = [int(q) for q in dst.split('.')]
        quads[3] = 1
        return "%d.%d.%d.%d" % (quads[0], quads[1], quads[2], quads[3])

    def send(self, network, message):
        print("Sending message to %s: %s" % (network, message))
        self.sockets[network].sendto(message.encode('utf-8'), ('localhost', self.ports[network]))

    def should_forward_to(self, src_relation, dst_neighbor):
        """Determine if we should forward updates based on BGP relationships."""
        dst_relation = self.relations[dst_neighbor]

        # From customer: announce to everyone
        if src_relation == 'cust':
            return True

        # From peer/provider: only announce to customers
        return dst_relation == 'cust'

    def handle_update(self, msg, src_interface):
        """Process route announcements."""
        update = msg['msg']
        src_relation = self.relations[src_interface]

        # Store the update
        self.updates.append((msg, src_interface))

        # Create route entry
        route = {
            'network': update['network'],
            'netmask': update['netmask'],
            'localpref': update.get('localpref', 100),
            'selfOrigin': update.get('selfOrigin', False),
            'ASPath': update.get('ASPath', []),
            'origin': update.get('origin', 'UNK'),
            'peer': msg['src']
        }

        # Don't process routes that loop back through our AS
        if self.asn in route['ASPath']:
            return

        # Update forwarding table
        self.add_or_update_route(route)

        # Forward update to appropriate neighbors
        forwarded_update = {
            'network': update['network'],
            'netmask': update['netmask'],
            'ASPath': [self.asn] + route['ASPath']
        }

        for neighbor in self.sockets:
            if neighbor != src_interface and self.should_forward_to(src_relation, neighbor):
                self.send(neighbor, json.dumps({
                    'src': self.our_addr(neighbor),
                    'dst': neighbor,
                    'type': 'update',
                    'msg': forwarded_update
                }))

    def add_or_update_route(self, new_route):
        """
        Add a new route to the forwarding table. Keep both routes if they're
        for the same network but from different peers.
        """
        # Find all existing routes for this network
        existing_routes = [r for r in self.forwarding_table
                           if r['network'] == new_route['network'] and
                           r['netmask'] == new_route['netmask']]

        # If we have a route from this peer already, update it
        peer_route_updated = False
        for i, route in enumerate(self.forwarding_table):
            if (route['network'] == new_route['network'] and
                    route['netmask'] == new_route['netmask'] and
                    route['peer'] == new_route['peer']):
                self.forwarding_table[i] = new_route
                peer_route_updated = True
                break

        # If we didn't update an existing route from this peer, add the new route
        if not peer_route_updated:
            self.forwarding_table.append(new_route)

    def compare_routes(self, route1, route2):
        """
        Compare two routes using BGP selection criteria.
        Returns True if route1 is preferred over route2.
        """
        # 1. Highest localpref wins
        loc1 = int(route1.get('localpref', 100))
        loc2 = int(route2.get('localpref', 100))
        if loc1 != loc2:
            return loc1 > loc2

        # 2. selfOrigin wins
        if route1.get('selfOrigin', False) != route2.get('selfOrigin', False):
            return route1.get('selfOrigin', False)

        # 3. Shortest ASPath wins
        if len(route1['ASPath']) != len(route2['ASPath']):
            return len(route1['ASPath']) < len(route2['ASPath'])

        # 4. Origin (IGP > EGP > UNK)
        origin_priority = {"IGP": 3, "EGP": 2, "UNK": 1}
        origin1 = origin_priority.get(route1.get('origin', 'UNK'), 0)
        origin2 = origin_priority.get(route2.get('origin', 'UNK'), 0)
        if origin1 != origin2:
            return origin1 > origin2

        # 5. Lowest peer IP (using tuple comparison)
        return ip_to_tuple(route1['peer']) < ip_to_tuple(route2['peer'])

    def lookup_route(self, dest_ip):
        """Find the best route for the given destination IP."""
        dest_int = ip_str_to_int(dest_ip)
        matching_routes = []
        best_prefix_len = -1

        # First find all matching routes
        for route in self.forwarding_table:
            # Convert netmask to prefix length (supports both dotted-decimal and prefix notation)
            prefix_len = netmask_to_prefix(route['netmask'])
            if ip_in_network(dest_ip, route['network'], prefix_len):
                if prefix_len > best_prefix_len:
                    best_prefix_len = prefix_len
                    matching_routes = [route]
                elif prefix_len == best_prefix_len:
                    matching_routes.append(route)

        if not matching_routes:
            return None

        # Among longest matches, find the best route
        best_route = matching_routes[0]
        for route in matching_routes[1:]:
            if self.compare_routes(route, best_route):
                best_route = route

        return best_route

    def can_forward_data(self, src_peer, dst_peer):
        """Check if data forwarding is allowed based on relationships."""
        src_relation = self.relations.get(src_peer)
        dst_relation = self.relations.get(dst_peer)

        # Always forward if source or destination is a customer
        if src_relation == 'cust' or dst_relation == 'cust':
            return True

        # Don't forward from peer/provider to peer/provider
        return False

    def handle_data(self, msg, src_interface):
        """Process data packets."""
        dest_ip = msg['dst']
        route = self.lookup_route(dest_ip)

        if route is None:
            # No route found
            self.send(src_interface, json.dumps({
                'src': self.our_addr(src_interface),
                'dst': msg['src'],
                'type': 'no route',
                'msg': {}
            }))
            return

        # Check if forwarding is allowed
        if not self.can_forward_data(src_interface, route['peer']):
            self.send(src_interface, json.dumps({
                'src': self.our_addr(src_interface),
                'dst': msg['src'],
                'type': 'no route',
                'msg': {}
            }))
            return

        # Forward the packet
        print(f"Forwarding data for {dest_ip} via peer {route['peer']}")
        self.send(route['peer'], json.dumps(msg))

    def handle_dump(self, msg, src_interface):
        """Respond to table dump requests."""
        self.send(msg['src'], json.dumps({
            'src': self.our_addr(msg['src']),
            'dst': msg['src'],
            'type': 'table',
            'msg': self.forwarding_table
        }))

    def handle_withdraw(self, msg, src_interface):
        """Handle route withdraw messages (stub implementation)."""
        # You can implement withdraw logic here
        print(f"Withdraw message received from {src_interface}: {msg}")
        self.withdraws.append((msg, src_interface))
        # For now, we do nothing further.

    def run(self):
        """Main event loop."""
        while True:
            socks = select.select(list(self.sockets.values()), [], [], 0.1)[0]
            for conn in socks:
                data, addr = conn.recvfrom(65535)
                src_interface = None
                for neighbor, sock in self.sockets.items():
                    if sock == conn:
                        src_interface = neighbor
                        break

                msg_str = data.decode('utf-8')
                try:
                    msg = json.loads(msg_str)
                except json.JSONDecodeError as e:
                    print(f"Failed to parse message: {msg_str}, {e}")
                    continue

                print(f"Received message '{msg_str}' from {src_interface}")

                if msg['type'] == 'update':
                    self.handle_update(msg, src_interface)
                elif msg['type'] == 'data':
                    self.handle_data(msg, src_interface)
                elif msg['type'] == 'dump':
                    self.handle_dump(msg, src_interface)
                elif msg['type'] == 'withdraw':
                    self.handle_withdraw(msg, src_interface)

            time.sleep(0.01)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='route packets')
    parser.add_argument('asn', type=int, help="AS number of this router")
    parser.add_argument('connections', metavar='connections', type=str, nargs='+',
                        help="connections")
    args = parser.parse_args()
    router = Router(args.asn, args.connections)
    router.run()
