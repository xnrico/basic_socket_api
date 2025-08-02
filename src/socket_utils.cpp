#include "socket_utils.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

namespace ricox {
auto get_iface_ip(const std::string& iface_name) -> std::string {
	char buf[NI_MAXHOST] = {'\0'};
	ifaddrs* ifaddr = nullptr;

	if (getifaddrs(&ifaddr) > -1) {
		for (ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr && ifa->ifa_name == iface_name && ifa->ifa_addr->sa_family == AF_INET) {
				if (getnameinfo(ifa->ifa_addr, sizeof(sockaddr_in), buf, sizeof(buf), nullptr, 0, NI_NUMERICHOST) ==
					0) {
					break;
				}
			}
		}
		freeifaddrs(ifaddr);
	}

	return std::string{buf};
}

auto set_non_blocking(int sockfd) -> bool {
	const auto flags = fcntl(sockfd, F_GETFL, 0);
	if (flags == -1) return false;
	// Set the socket to non-blocking mode
	return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) != -1;
}

auto set_no_delay(int sockfd) -> bool {	 // Disable Nagle's algorithm for TCP sockets
	// This is used to send small packets immediately without waiting for more data
	// It is useful for real-time applications where low latency is required
	// The TCP_NODELAY option is used to disable Nagle's algorithm
	const auto flag = int{1};
	return setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const void*>(&flag), sizeof(flag)) != -1;
}

auto would_block() -> bool {
	// Check if the last operation would block
	return errno == EINPROGRESS || errno == EWOULDBLOCK;
}

auto set_mcast_ttl(int sockfd, const int ttl) -> bool {
	// Set the multicast Time-To-Live (TTL) for the socket
	return setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const void*>(&ttl), sizeof(ttl)) != -1;
}

auto set_ttl(int sockfd, const int ttl) -> bool {
	// Set the Time-To-Live (TTL) for the socket
	return setsockopt(sockfd, IPPROTO_IP, IP_TTL, reinterpret_cast<const void*>(&ttl), sizeof(ttl)) != -1;
}

auto set_so_timestamp(int sockfd) -> bool {
	// Enable socket timestamping in case no hardware timestamping is available
	// This is useful for applications that need to know when packets are sent or received
	const auto flag = int{1};
	return setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMP, reinterpret_cast<const void*>(&flag), sizeof(flag)) != -1;
}

// Socket creation functions
auto create_socket(const std::string& t_ip, const std::string& iface_name, int port, bool is_blocking,
				   bool is_listening, int ttl, bool needs_so_timestamp, bool is_udp) -> int {
	auto time_str = std::string{};
	const auto ip = t_ip.empty() ? get_iface_ip(iface_name) : t_ip;

	std::cout << "Creating " << (is_udp ? "UDP" : "TCP") << " socket on interface: " << iface_name << ", IP: " << ip
			  << ", Port: " << port << ", Blocking: " << is_blocking << ", Listening: " << is_listening
			  << ", TTL: " << ttl << ", SO_TIMESTAMP: " << needs_so_timestamp << std::endl;

	auto hints = addrinfo{};
	hints.ai_family = AF_INET;	// IPv4
	hints.ai_socktype = is_udp ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = is_udp ? IPPROTO_UDP : IPPROTO_TCP;
	hints.ai_flags = is_listening ? AI_PASSIVE : 0;				   // AI_PASSIVE for server sockets
	if (std::isdigit(ip.at(0))) hints.ai_flags |= AI_NUMERICHOST;  // Use numeric IP address
	hints.ai_flags |= AI_NUMERICSERV;							   // Use numeric port

	addrinfo* res = nullptr;
	const auto status = getaddrinfo(ip.c_str(), std::to_string(port).c_str(), &hints, &res);
	if (status != 0) {
		std::cerr << "getaddrinfo failed: " << gai_strerror(status) << std::endl;
		return -1;
	}

	// create socket with the correct parameters
	auto sockfd = int{-1};
	const auto flag = int{1};

	for (auto* p = res; p != nullptr; p = p->ai_next) {
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

		if (sockfd == -1) {
			std::cerr << "socket creation failed: " << strerror(errno) << std::endl;
			return -1;
		}

		if (!is_blocking) {
			if (!set_non_blocking(sockfd)) {
				std::cerr << "Failed to set non-blocking mode: " << strerror(errno) << std::endl;
				close(sockfd);
				return sockfd = -1;
			}

			if (!is_udp && !set_no_delay(sockfd)) {
				std::cerr << "Failed to set TCP_NODELAY: " << strerror(errno) << std::endl;
				close(sockfd);
				return sockfd = -1;
			}
		}

		if (!is_listening && connect(sockfd, p->ai_addr, p->ai_addrlen) == 1 && would_block()) {
			std::cerr << "Connection would block, socket is non-blocking: " << strerror(errno) << std::endl;
			return sockfd = -1;
		}

		if (is_listening && setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const void*>(&flag),
									   sizeof(flag)) == -1) {  // Allow reuse of the address
			std::cerr << "Failed to set SO_REUSEADDR: " << strerror(errno) << std::endl;
			close(sockfd);
			return sockfd = -1;
		}

		if (is_listening && bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			std::cerr << "bind failed: " << strerror(errno) << std::endl;
			close(sockfd);
			return sockfd = -1;
		}

		if (!is_udp && is_listening && listen(sockfd, MAX_TCP_SERVER_BACKLOG) == -1) {
			std::cerr << "listen failed: " << strerror(errno) << std::endl;
			close(sockfd);
			return sockfd = -1;
		}

		if (is_udp && ttl > 0) {
			const auto is_multicast =
				std::atoi(ip.c_str()) & 0xE0;  // Check if the IP is a multicast address (224.0.0.0/4)
			if (is_multicast && !set_mcast_ttl(sockfd, ttl)) {
				std::cerr << "Failed to set multicast TTL: " << strerror(errno) << std::endl;
				close(sockfd);
				return sockfd = -1;
			} else if (!is_multicast && !set_ttl(sockfd, ttl)) {
				std::cerr << "Failed to set TTL: " << strerror(errno) << std::endl;
				close(sockfd);
				return sockfd = -1;
			}
		}

		if (needs_so_timestamp && !set_so_timestamp(sockfd)) {
			std::cerr << "Failed to set SO_TIMESTAMP: " << strerror(errno) << std::endl;
			close(sockfd);
			return sockfd = -1;
		}
	}

	if (res) freeaddrinfo(res);
	return sockfd;
}

auto create_tcp_socket(const std::string& t_ip, const std::string& iface_name, int port, bool is_blocking,
					   bool is_listening, int ttl, bool needs_so_timestamp) -> int {
	return create_socket(t_ip, iface_name, port, is_blocking, is_listening, ttl, needs_so_timestamp, false);
}

auto create_udp_socket(const std::string& t_ip, const std::string& iface_name, int port, bool is_blocking, int ttl,
					   bool needs_so_timestamp) -> int {
	return create_socket(t_ip, iface_name, port, is_blocking, false, ttl, needs_so_timestamp, true);
}
}  // namespace ricox