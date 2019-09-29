cmake_minimum_required(VERSION 3.12.0)

project(mbedtls_vs_openssl)

link_directories(/Users/byredance/p2p/mediasoup/worker/out/Debug
	/Users/byredance/p2p/mediasoup/worker/deps/mbedtls/build/library
	/Users/byredance/p2p/mediasoup/worker/deps/mbedtls/build/crypto/library
)

include_directories(
	/Users/byredance/p2p/mediasoup/worker/deps/mbedtls/include
	/Users/byredance/p2p/mediasoup/worker/deps/mbedtls/crypto/include
	/Users/byredance/p2p/mediasoup/worker/deps/openssl/openssl/include
)

add_executable(main 
	main.cpp)
target_link_libraries(main openssl mbedtls mbedx509 mbedcrypto)
