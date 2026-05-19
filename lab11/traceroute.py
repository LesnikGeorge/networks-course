import socket
import struct
import time
import select
import sys
import os
import argparse

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
ICMP_DEST_UNREACHABLE = 3

def calculate_checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += (checksum >> 16)
    
    return (~checksum) & 0xFFFF

def create_icmp_packet(packet_id: int, sequence: int) -> bytes:
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, packet_id, sequence)
    data = b'abcdefghijklmnopqrstuvwabcdefghi'
    
    chksum = calculate_checksum(header + data)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, packet_id, sequence)
    return header + data

def traceroute(target_host: str, max_hops: int, queries: int, timeout: float):
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"Не удалось разрешить имя хоста: {target_host}")
        return

    print(f"Трассировка маршрута к {target_host} [{target_ip}]")
    print(f"С максимальным числом прыжков {max_hops}, запросов на прыжок {queries}:\n")
    print(f"{'Прыжок':<8} {'IP-адрес':<18} {'Имя узла':<40} {'Время (RTT)'}")
    print("-" * 80)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Ошибка: Требуются права администратора (sudo)!")
        sys.exit(1)

    pid = os.getpid() & 0xFFFF
    target_reached = False
    seq_counter = 1

    for ttl in range(1, max_hops + 1):
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        
        rtts = []
        hop_ip = None
        hop_name = ""

        for q in range(queries):
            packet = create_icmp_packet(pid, seq_counter)
            
            send_time = time.time()
            sock.sendto(packet, (target_ip, 1))
            seq_counter += 1
            
            time_left = timeout
            match_found = False

            while time_left > 0:
                start_select = time.time()
                ready = select.select([sock], [], [], time_left)
                time_left -= time.time() - start_select
                
                if not ready[0]:
                    break
                    
                recv_time = time.time()
                recv_packet, addr = sock.recvfrom(1024)
                
                ip_header_len = (recv_packet[0] & 0x0F) * 4
                if len(recv_packet) < ip_header_len + 8:
                    continue
                    
                icmp_header = recv_packet[ip_header_len:ip_header_len+8]
                icmp_type, icmp_code, _, recv_id, recv_seq = struct.unpack("!BBHHH", icmp_header)
                
                if icmp_type == ICMP_TIME_EXCEEDED or icmp_type == ICMP_DEST_UNREACHABLE:

                    inner_ip_start = ip_header_len + 8

                    if len(recv_packet) >= inner_ip_start + 20:

                        inner_ip_header_len = (recv_packet[inner_ip_start] & 0x0F) * 4
                        inner_icmp_start = inner_ip_start + inner_ip_header_len
                        
                        if len(recv_packet) >= inner_icmp_start + 8:

                            inner_icmp_header = recv_packet[inner_icmp_start:inner_icmp_start+8]
                            _, _, _, orig_id, orig_seq = struct.unpack("!BBHHH", inner_icmp_header)
                            
                            if orig_id == pid and orig_seq == seq_counter - 1:

                                rtt = (recv_time - send_time) * 1000
                                rtts.append(f"{rtt:.1f} мс")
                                hop_ip = addr[0]
                                match_found = True
                                if icmp_type == ICMP_DEST_UNREACHABLE:
                                    target_reached = True
                                break

                elif icmp_type == ICMP_ECHO_REPLY:

                    if recv_id == pid and recv_seq == seq_counter - 1:

                        rtt = (recv_time - send_time) * 1000
                        rtts.append(f"{rtt:.1f} мс")
                        hop_ip = addr[0]
                        match_found = True
                        target_reached = True
                        break
            
            if not match_found:
                rtts.append("*")

        if hop_ip:
            try:
                hop_name = socket.gethostbyaddr(hop_ip)[0]
            except socket.herror:
                hop_name = "" 
        else:
            hop_ip = "Превышен интервал ожидания"

        rtt_str = "  ".join(rtts)
        print(f"{ttl:<8} {hop_ip:<18} {hop_name:<40} {rtt_str}")

        if target_reached:
            print("\nТрассировка завершена.")
            break

    sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Своя реализация Traceroute (ICMP)")
    parser.add_argument("host", help="Целевой хост (например, google.com)")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Максимальное количество прыжков")
    parser.add_argument("-q", "--queries", type=int, default=3, help="Количество запросов на прыжок")
    parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Таймаут (сек)")

    args = parser.parse_args()
    traceroute(args.host, args.max_hops, args.queries, args.timeout)