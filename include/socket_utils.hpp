#pragma once

#include <string>

namespace ricox {
constexpr int MAX_TCP_SERVER_BACKLOG = 1024;

auto get_iface_ip(const std::string& iface_name) -> std::string;
auto set_non_blocking(int sockfd) -> bool;
auto set_no_delay(int sockfd) -> bool;
auto set_so_timestamp(int sockfd) -> bool;
auto would_block() -> bool;
auto set_mcast_ttl(int sockfd, const int ttl) -> bool;
auto set_ttl(int sockfd, const int ttl) -> bool;
auto join(int sockfd, const std::string& ip, const std::string& iface_name, int port) -> bool;
auto create_socket(const std::string& t_ip, const std::string& iface_name, int port, bool is_blocking,
				   bool is_listening, int ttl, bool needs_so_timestamp, bool is_udp = false) -> int;
auto create_tcp_socket(const std::string& t_ip, const std::string& iface_name, int port, bool is_blocking,
					   bool is_listening, int ttl, bool needs_so_timestamp) -> int;
auto create_udp_socket(const std::string& t_ip, const std::string& iface_name, int port, bool is_blocking, int ttl,
					   bool needs_so_timestamp) -> int;
}  // namespace ricox