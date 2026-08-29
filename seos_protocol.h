#pragma once

#include <mbedtls/des.h>
#include <mbedtls/aes.h>

#include "seos_credential.h"
#include "secure_messaging.h"

/* The Seos exchange itself: selecting an application, agreeing a session key,
 * and the cryptograms on either side of it.
 *
 * This is transport neutral. The NFC poller and listener drive it, and so do
 * the BLE stacks, which is why it does not live with either of them.
 */

/* Status words the exchange answers with. */
extern const uint8_t SEOS_SW_SUCCESS[2];
extern const uint8_t SEOS_SW_FILE_NOT_FOUND[2];

/* Card side. */
void seos_emulator_select_aid(BitBuffer* tx_buffer, const uint8_t* aid, size_t aid_len);

bool seos_emulator_select_adf(
    const uint8_t* oid_list,
    size_t oid_list_len,
    AuthParameters* params,
    SeosCredential* credential,
    BitBuffer* tx_buffer);

void seos_emulator_general_authenticate_1(BitBuffer* tx_buffer, AuthParameters params);

bool seos_emulator_general_authenticate_2(
    const uint8_t* buffer,
    size_t buffer_len,
    SeosCredential* credential,
    AuthParameters* params,
    BitBuffer* tx_buffer);

/* Reader side. */
bool seos_reader_select_adf_response(
    BitBuffer* rx_buffer,
    size_t offset,
    SeosCredential* credential,
    AuthParameters* params);

void seos_reader_generate_cryptogram(
    SeosCredential* credential,
    AuthParameters* params,
    uint8_t* cryptogram);

bool seos_reader_verify_cryptogram(AuthParameters* params, const uint8_t* cryptogram);
