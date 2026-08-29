# Host test suite.
#
#   make test-host   build and run the suite on this machine
#
# The app's own sources are compiled directly against the shims in
# lib/host_tests, so the tests exercise the same code the firmware runs.
# mbedTLS 4 dropped DES, so a 3.x install is preferred when one is present.

HOST_TESTS := lib/host_tests
MUNIT      := $(HOST_TESTS)/vendor/munit

MBEDTLS_PREFIX := $(firstword $(wildcard /opt/homebrew/opt/mbedtls@3 /usr/local/opt/mbedtls@3))

HOST_TEST_CFLAGS := -std=c11 -Wall -Wextra -Werror -g -I. -I$(HOST_TESTS) -I$(MUNIT) -Ible_shared
HOST_TEST_LDFLAGS := -lmbedcrypto
ifneq ($(MBEDTLS_PREFIX),)
HOST_TEST_CFLAGS  += -I$(MBEDTLS_PREFIX)/include
HOST_TEST_LDFLAGS += -L$(MBEDTLS_PREFIX)/lib
endif

HOST_TEST_SUPPORT := \
	$(MUNIT)/munit.c \
	$(HOST_TESTS)/bit_buffer_mock.c \
	$(HOST_TESTS)/furi_hal_mock.c \
	$(HOST_TESTS)/test_helpers.c \
	$(HOST_TESTS)/keys_stub.c

HOST_TEST_SOURCES := \
	$(HOST_TESTS)/test_main.c \
	$(HOST_TESTS)/test_cmac.c \
	$(HOST_TESTS)/test_kdf.c \
	$(HOST_TESTS)/test_secure_messaging.c \
	$(HOST_TESTS)/test_protocol.c \
	$(HOST_TESTS)/test_sm_command.c \
	$(HOST_TESTS)/test_ble_policy.c \
	$(HOST_TESTS)/test_ble_framing.c \
	$(HOST_TESTS)/test_session_vectors.c \
	$(HOST_TESTS)/test_emulated_card.c

HOST_TEST_APP_SOURCES := \
	cmac.c \
	seos_common.c \
	secure_messaging.c \
	seos_protocol.c \
	seos_sm_command.c \
	seos_ble_policy.c \
	ble_shared/seos_ble_framing.c \
	memmem.c

.PHONY: test-host clean-host

test-host:
	@mkdir -p build/host_tests
	$(CC) $(HOST_TEST_CFLAGS) \
		$(HOST_TEST_SUPPORT) $(HOST_TEST_SOURCES) $(HOST_TEST_APP_SOURCES) \
		-o build/host_tests/seos_tests $(HOST_TEST_LDFLAGS)
	./build/host_tests/seos_tests

clean-host:
	rm -rf build/host_tests
