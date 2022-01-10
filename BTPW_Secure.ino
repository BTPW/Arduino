#include <SHA512.h>
#include <RNG.h>
#include <RingOscillatorNoiseSource.h>
#include <stdint.h>
#include <EEPROM.h>
#include <AES.h>
#include <Keyboard.h>

//#define DEBUG

#define KEY_SIZE 32
#define VERSION_ID "BTPW v0.1.0"
#define EEPROM_DATA_CANARY 0xDEADCAFE
#define DEVICE_NAME_SIZE 4
#define BLOCK_SIZE 16
#define STATE_COUNT 8
#define KEF_TIMEOUT 5000
#define KEF_TIMEOUT_CANCEL 10000

// CJMU Beetle ports:
// SCL - D0
// SDA - D1
// RX  - D2  (Arduino pin "D0")
// TX  - D3  (Arduino pin "D1")
// D11 - B7
// D10 - B6
// D9  - B5
// A0  - F7
// A1  - F6
// A2  - F5
// SCK - B1
// MO  - B2
// MI  - B3

const char HEX_LOOKUP[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
const char BLOCK_VERIFY_CANARY[6] = { 'C', '4', 'N', 'A', '2', 'Y' };
const uint8_t DISPLAY_LOOKUP[16] = {
  0b01101111 ^ 0b11101111,
  0b00000110 ^ 0b11101111,
  0b10101011 ^ 0b11101111,
  0b10001111 ^ 0b11101111,
  0b11000110 ^ 0b11101111,
  0b11001101 ^ 0b11101111,
  0b11101101 ^ 0b11101111,
  0b00000111 ^ 0b11101111,
  0b11101111 ^ 0b11101111,
  0b11001111 ^ 0b11101111,
  0b11100111 ^ 0b11101111,
  0b11101100 ^ 0b11101111,
  0b01101001 ^ 0b11101111,
  0b10101110 ^ 0b11101111,
  0b11101001 ^ 0b11101111,
  0b11100001 ^ 0b11101111
};

// HEX display ports:
/*
 * D0 - a
 * B1 - b
 * B2 - c
 * B3 - d
 * -- - NC
 * B5 - e
 * B6 - f
 * B7 - g
 * 
 * PORTB bitmask: 0b11101110
 * PORTD bitmask: 0b00000001
 */

typedef uint64_t raw_key;

struct EEPROMData {
  uint32_t canary;                    // If canary loaded from EEPROM is not equal to EEPROM_DATA_CANARY, assume data is not valid
  char device_name[DEVICE_NAME_SIZE]; // Device ID: DEVICE_NAME_SIZE * 2 hexadecimal characters
  char has_key;                       // This flag should only be 0 after first initialization. This prevents attacks targeting default EEPROM state
  char key[KEY_SIZE];                 // Saved encryption key for secure communication
};

struct KEFState {
  raw_key key;
  char key_hash[KEY_SIZE];
  char generating : 1;
  size_t index : 4;
  unsigned long last_comm;
};

enum Command {
  NONE,
  
  KEF_INIT,
  KEF_NEXT,
  KEF_BACK,
  KEF_CANCEL,
  KEF_HEARTBEAT,
  KEF_VERIFY,

  ENCRYPTED
};

enum EncryptedCommand {
  SEND_KEYSTROKE
};

struct CommandData {
  enum EncryptedCommand command;
  uint16_t aux;
  uint8_t next_offset;
};


SHA512 hash;
AES256 aes;
RingOscillatorNoiseSource roNoise;
struct EEPROMData eeprom_data;
uint8_t next_offset;
enum Command current_state;

// Transient values used during key establishment
struct KEFState kef_state;
uint8_t aes_data[BLOCK_SIZE];
char decrypted[BLOCK_SIZE];
char raw_enc_data[BLOCK_SIZE * 2];
uint8_t enc_data_index;



void init_rng() {
  RNG.begin(VERSION_ID);
  RNG.addNoiseSource(roNoise);
}

// Assumes that RNG is configured
void init_eeprom() {
  RNG.loop();

  char * eeprom_data_c = (char *)&eeprom_data;
  for (signed i = sizeof(EEPROMData) - 1; i >= 0; --i) {
    eeprom_data_c[i] = EEPROM[i];
  }

  if (eeprom_data.canary != EEPROM_DATA_CANARY) {
    // Initialize eeprom data
    RNG.rand((uint8_t *)eeprom_data.device_name, DEVICE_NAME_SIZE);
    eeprom_data.has_key = 0;
    eeprom_data.canary = EEPROM_DATA_CANARY;

    save_eeprom_data();
  }
}

// Save data to eeprom
void save_eeprom_data() {
  char * eeprom_data_c = (char *)&eeprom_data;
  for (signed i = sizeof(EEPROMData) - 1; i >= 0; --i) {
    EEPROM[i] = eeprom_data_c[i];
  }
}

// Result of hashing is stored in global hash_result
// Do not call this on a generated key until peer is requesting a verification
// This should mitigate SCA somewhat
void do_hash() {
  hash.reset();
  hash.update(&kef_state.key, sizeof(raw_key));
  hash.finalize(kef_state.key_hash, KEY_SIZE);
}

raw_key regen_key() {
  raw_key key;
  RNG.rand((uint8_t *)&key, sizeof(key));
  return key;
}

char to_hex(raw_key key, size_t index) {
  return HEX_LOOKUP[(key >> (index * 4)) & 0xF];
}

void print_display(char value) {
  PORTD = DISPLAY_LOOKUP[value & 15] & 0b00000001;
  PORTB = DISPLAY_LOOKUP[value & 15] & 0b11101110;
}

void clear_display() {
  PORTD = 0b00000001;
  PORTB = 0b11101110;
}

void kef_init() {
  kef_state.key = regen_key();
  kef_state.index = 0;
  kef_state.generating = 1;
  print_display(kef_state.key & 0xF);
}

void kef_cancel() {
  kef_state.generating = 0;
  clear_display();
}

void kef_next() {
  if (kef_state.generating && kef_state.index < 15) {
    print_display((kef_state.key >> (++kef_state.index * 4)) & 0xF);
  }
}

void kef_back() {
  if (kef_state.generating && kef_state.index > 0) {
    print_display((kef_state.key >> (--kef_state.index * 4)) & 0xF);
  }
}

char kef_verify() {
  do_hash();
  aes.setKey((uint8_t *)kef_state.key_hash, KEY_SIZE);
  aes.decryptBlock((uint8_t *)decrypted, aes_data);

  uint8_t padding = read_block_padding();
  kef_state.generating = 0;
  if (padding <= (BLOCK_SIZE - sizeof(CommandData))) {
    memcpy(eeprom_data.key, (void *)kef_state.key, KEY_SIZE);
    save_eeprom_data();
    next_offset = padding;
    return 1;
  }
  aes.setKey((uint8_t *)eeprom_data.key, KEY_SIZE);
  return 0;
}

char parse_hex(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  } else if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  } else if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  } else {
    return 0;
  }
}

char is_hex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

char ensure_raw_hex() {
  for (size_t s = 0; s < sizeof(raw_enc_data); ++s) {
    if (!is_hex(raw_enc_data[s])) {
      return 0;
    }
  }
  return 1;
}

void hex_decode_raw() {
  memset(aes_data, 0, sizeof(aes_data));
  for (size_t s = 0; s < sizeof(raw_enc_data); ++s) {
    aes_data[s >> 1] |= parse_hex(raw_enc_data[s]) << ((s & 1) << 2);
  }
}

uint8_t read_block_padding() {
  uint8_t match_count = 0;
  uint8_t t = 0;
  for (; (t < (BLOCK_SIZE - 1 + match_count - sizeof(BLOCK_VERIFY_CANARY))) && (match_count - sizeof(BLOCK_VERIFY_CANARY)); ++t) {
    if (decrypted[t] == BLOCK_VERIFY_CANARY[match_count]) {
      ++match_count;
    } else {
      match_count = 0;
    }
  }

  if (match_count != sizeof(BLOCK_VERIFY_CANARY)) {
    return sizeof(BLOCK_VERIFY_CANARY);
  }

  return (uint8_t)decrypted[t];
}

struct CommandData read_command_data(uint8_t offset) {
  return *(struct CommandData *)(&decrypted[offset]);
}

void setup() {
  //while (1);
  // Initialize ports
  DDRD |= 0b00000001;
  DDRB |= 0b11101110;
  
  init_rng();
  init_eeprom();
  clear_display();

  aes.setKey((uint8_t *)eeprom_data.key, KEY_SIZE);
  kef_state.generating = 0;
  current_state = NONE;

  Keyboard.begin();
  Serial1.begin(9600);
#ifdef DEBUG
  Serial.begin(115200);
#endif
}

enum Command read_next_state() {
  if (Serial1.available()) {
    char new_state = Serial1.read();
#ifdef DEBUG
    Serial.print(new_state);
#endif
    uint8_t state_value;
    if (is_hex(new_state) && ((state_value = parse_hex(new_state)) < STATE_COUNT)) {
      current_state = (enum Command)state_value;
      enc_data_index = 0;
      return current_state;
    }
  }
  return NONE;
}

int8_t read_block() {
  if (Serial1.available() && enc_data_index < sizeof(raw_enc_data)) {
    raw_enc_data[enc_data_index++] = Serial1.read();
#ifdef DEBUG
    Serial.print(raw_enc_data[enc_data_index - 1]);
#endif
  }
  
  if (enc_data_index == sizeof(raw_enc_data)) {
    enc_data_index = 0;
    
    // Do decryption here
    if (!ensure_raw_hex()) {
      current_state = NONE; // Invalid encrypted data
      return -1;
    }
    hex_decode_raw();
    return 1;
  }

  return 0;
}

void loop() {
  switch(current_state) {
    case NONE: {
      // Await command from remote device
      read_next_state();
      break;
    }

    case ENCRYPTED: {
      int8_t read_result = read_block();
      aes.decryptBlock((uint8_t *)decrypted, aes_data);

      if (read_result == 1) {
        struct CommandData command_data = read_command_data(next_offset);
        if (command_data.next_offset > BLOCK_SIZE - sizeof(struct CommandData)) {
          current_state = NONE; // Invalid next offset
          break;
        }

        next_offset = command_data.next_offset;

        switch(command_data.command) {
          case SEND_KEYSTROKE:
            Keyboard.write(command_data.aux & 0xFF); // Send low bytes as key character
            break;
        }
        Serial1.println("OK");
      } else if(read_result == -1) {
        Serial1.println("NO");
      }
      break;
    }

    case KEF_INIT: {
      if(!kef_state.generating) {
        kef_init();
        kef_state.last_comm = millis();
        Serial1.println("Initiated");
      }
      enum Command new_state = read_next_state();
      if (new_state == KEF_INIT) {
        kef_state.generating = 0;
      }
      break;
    }

    case KEF_CANCEL: {
      if (kef_state.generating) {
        kef_cancel();
        Serial1.println("Cancelled");
        current_state = NONE;
      }
      break;
    }

    case KEF_NEXT: {
      if (kef_state.generating) {
        kef_next();
        kef_state.last_comm = millis();
        Serial1.println("Next");
        current_state = KEF_INIT;
      }
      break;
    }

    case KEF_BACK: {
      if (kef_state.generating) {
        kef_back();
        kef_state.last_comm = millis();
        Serial1.println("Back");
        current_state = KEF_INIT;
      }
      break;
    }

    case KEF_HEARTBEAT: {
      if (kef_state.generating) {
        Serial1.println("H3RTB34T"); // Heartbeat message :)
        kef_state.last_comm = millis();
        current_state = KEF_INIT;
      }
      break;
    }

    case KEF_VERIFY: {
      if (kef_state.generating) {
        int8_t read_result = read_block();
        if (read_result == 1 && kef_verify()) {
          Serial1.println("OK");
          current_state = NONE;
        } else if (read_result == -1) {
          Serial1.println("NO");
          current_state = NONE;
        }
      }
      break;
    }

    default: {
      
    }
  }
  
  if (current_state == KEF_INIT) {
    unsigned long time_since = millis() - kef_state.last_comm;
    if (time_since > KEF_TIMEOUT_CANCEL) {
      Serial.println("Cancelled");
      kef_cancel();
      current_state = NONE;
    } else if (time_since > KEF_TIMEOUT) {
      Serial.println("HEARTBEAT?");
    }
  }
}
