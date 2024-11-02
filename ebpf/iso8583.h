// Contents: Header file for ISO 8583 message format
#ifndef ISO8583_H
#define ISO8583_H

#include <stddef.h>
#include "headers/bpf_endian.h"
#include "headers/common.h"

#define ISO8583_MAX_FIELDS 128

#define ISO8583_MIN_SIZE sizeof(struct iso8583_message)

enum iso8583_field_type {
    ISO8583_TYPE_STRING,
    ISO8583_TYPE_NUMERIC,
    ISO8583_TYPE_BITMAP,
};

enum iso8583_field_prefix {
    ISO8583_PREFIX_FIXED,
    ISO8583_PREFIX_LLVAR,
    ISO8583_PREFIX_LLLVAR,
};

struct iso8583_field_definition {
    int field_number;
    enum iso8583_field_type type;
    u16 length;
    enum iso8583_field_prefix prefix;
};

struct iso8583_field {
    enum iso8583_field_type type;
    u16 length;
    const char *value;
};


#define BITMAP_SIZE 16
struct iso8583_bitmap {
    u8 bitmap[BITMAP_SIZE]; // 128 bits representing fields 1-128
};

#define MTI_SIZE 4
struct iso8583_message {
    unsigned char lsb;
    unsigned char msb;
    unsigned char message_type_indicator[MTI_SIZE]; // Field 0: 4 characters
    struct iso8583_bitmap bitmap;   // Field 1: 128-bit bitmap
};

// Custom strtoul function optimized for eBPF
static __always_inline unsigned long iso8583_strtoul(const char *nptr, __u16 *result, int base, int len) {
    unsigned long res = 0;
    for(int i = 0; i < len; i++) {
        char c = nptr[i];
        if (c < '0' || c > '9') {
            return 0; // Invalid character encountered
        }
        res = res * base + (c - '0');
    }
    *result = res;
    return 1; // Success
}

// struct iso8583_fields fields[ISO8583_MAX_FIELDS + 1]; // Includes field 0

// Function to parse the size of the message
static __always_inline __u16 iso8583_parse_size(const struct iso8583_message *message){
    __u16 size = (message->msb << 8) | message->lsb;
    return size;
}

// Function to parse a message
static __always_inline int iso8583_parse_message(void *data, struct iso8583_message *message, __u16 size) {
    if (data == NULL || message == NULL) {
        return -1;
    }

    return 0;

}

static inline int hex_char_to_value(char c) {
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= '0' && c <= '9') {
        return c - '0';
    } else {
        return -1;
    }
}

static __always_inline int iso8583_is_field_present(const struct iso8583_message *message, int field_number) {
    int adjusted_field = field_number - 1;

    if (adjusted_field < 0 || adjusted_field >= ISO8583_MAX_FIELDS) {
        return 0;
    }

    int hex_digit_index = adjusted_field / 4;

    if (hex_digit_index >= BITMAP_SIZE) {
        return 0;
    }

    char hex_char = message->bitmap.bitmap[hex_digit_index];
    int bitmap_value = hex_char_to_value(hex_char);

    if (bitmap_value < 0) {
        return 0;
    }

    int bit_position = 3 - (adjusted_field % 4); // Bits: 3 (MSB) a 0 (LSB)

    int mask = 1 << bit_position;

    bpf_printk("bitmap nibble: 0x%x\n", bitmap_value);

    return (bitmap_value & mask) ? 1 : 0;
}

// Field definitions
static const struct iso8583_field_definition iso8583_field_definitions[] = {
    {1, ISO8583_TYPE_BITMAP, 16,  ISO8583_PREFIX_FIXED},
    {2, ISO8583_TYPE_STRING, 19,  ISO8583_PREFIX_LLVAR},
    {3, ISO8583_TYPE_NUMERIC, 6,  ISO8583_PREFIX_FIXED},
    {4, ISO8583_TYPE_STRING, 12,  ISO8583_PREFIX_FIXED},
    {5, ISO8583_TYPE_STRING, 12,  ISO8583_PREFIX_FIXED},
    {6, ISO8583_TYPE_STRING, 12,  ISO8583_PREFIX_FIXED},
    {7, ISO8583_TYPE_STRING, 10,  ISO8583_PREFIX_FIXED},
    {8, ISO8583_TYPE_STRING, 8,  ISO8583_PREFIX_FIXED},
    {9, ISO8583_TYPE_STRING, 8,  ISO8583_PREFIX_FIXED},
    {10, ISO8583_TYPE_STRING, 8,  ISO8583_PREFIX_FIXED},
    {11, ISO8583_TYPE_STRING, 6,  ISO8583_PREFIX_FIXED},
    {12, ISO8583_TYPE_STRING, 6,  ISO8583_PREFIX_FIXED},
    {13, ISO8583_TYPE_STRING, 4,  ISO8583_PREFIX_FIXED},
    {14, ISO8583_TYPE_STRING, 4,  ISO8583_PREFIX_FIXED},
    {15, ISO8583_TYPE_STRING, 4,  ISO8583_PREFIX_FIXED},
    {16, ISO8583_TYPE_STRING, 4,  ISO8583_PREFIX_FIXED},
    {17, ISO8583_TYPE_STRING, 4,  ISO8583_PREFIX_FIXED},
    {18, ISO8583_TYPE_STRING, 4,  ISO8583_PREFIX_FIXED},
    {19, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {20, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {21, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {22, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {23, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {24, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {25, ISO8583_TYPE_STRING, 2,  ISO8583_PREFIX_FIXED},
    {26, ISO8583_TYPE_STRING, 2,  ISO8583_PREFIX_FIXED},
    {27, ISO8583_TYPE_STRING, 1,  ISO8583_PREFIX_FIXED},
    {28, ISO8583_TYPE_STRING, 9,  ISO8583_PREFIX_FIXED},
    {29, ISO8583_TYPE_STRING, 9,  ISO8583_PREFIX_FIXED},
    {30, ISO8583_TYPE_STRING, 9,  ISO8583_PREFIX_FIXED},
    {31, ISO8583_TYPE_STRING, 9,  ISO8583_PREFIX_FIXED},
    {32, ISO8583_TYPE_STRING, 11,  ISO8583_PREFIX_LLVAR},
    {33, ISO8583_TYPE_STRING, 11,  ISO8583_PREFIX_LLVAR},
    {34, ISO8583_TYPE_STRING, 28,  ISO8583_PREFIX_LLVAR},
    {35, ISO8583_TYPE_STRING, 37,  ISO8583_PREFIX_LLVAR},
    {36, ISO8583_TYPE_STRING, 104,  ISO8583_PREFIX_LLLVAR},
    {37, ISO8583_TYPE_STRING, 12,  ISO8583_PREFIX_FIXED},
    {38, ISO8583_TYPE_STRING, 6,  ISO8583_PREFIX_FIXED},
    {39, ISO8583_TYPE_STRING, 2,  ISO8583_PREFIX_FIXED},
    {40, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {41, ISO8583_TYPE_STRING, 8,  ISO8583_PREFIX_FIXED},
    {42, ISO8583_TYPE_STRING, 15,  ISO8583_PREFIX_FIXED},
    {43, ISO8583_TYPE_STRING, 40,  ISO8583_PREFIX_FIXED},
    {44, ISO8583_TYPE_STRING, 99,  ISO8583_PREFIX_LLVAR},
    {45, ISO8583_TYPE_STRING, 76,  ISO8583_PREFIX_LLVAR},
    {46, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {47, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {48, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {49, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {50, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {51, ISO8583_TYPE_STRING, 3,  ISO8583_PREFIX_FIXED},
    {52, ISO8583_TYPE_STRING, 8,  ISO8583_PREFIX_FIXED},
    {53, ISO8583_TYPE_STRING, 16,  ISO8583_PREFIX_FIXED},
    {54, ISO8583_TYPE_STRING, 120,  ISO8583_PREFIX_LLLVAR},
    {55, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {56, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {57, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {58, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {59, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {60, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {61, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {62, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {63, ISO8583_TYPE_STRING, 999,  ISO8583_PREFIX_LLLVAR},
    {64, ISO8583_TYPE_STRING, 8,  ISO8583_PREFIX_FIXED},
    {90, ISO8583_TYPE_STRING, 42,  ISO8583_PREFIX_FIXED}
};

// Function to get a field by number
static __always_inline int iso8583_get_field(const struct iso8583_message *message, int field_number, struct iso8583_field *out_field, void *data_end) {
    // Validate field_number early
    if (field_number <= 0 || field_number > ISO8583_MAX_FIELDS) {
        bpf_printk("Invalid field number: %d\n", field_number);
        return 0; // Failure
    }

    // Check if the field is present
    if (!iso8583_is_field_present(message, field_number)) {
        return 0; // Failure
    }

    __u16 offset = 0;
    const char *data = (const char *)(message + 1); // Assuming data starts right after the message struct

    if (field_number == 0){
        out_field->type = ISO8583_TYPE_BITMAP;
        out_field->length = 16;
        out_field->value = message->bitmap.bitmap;
        return 1;
    }

    #pragma clang loop unroll(full)
    for (int i = 1; i <= field_number; i++) {
        const struct iso8583_field_definition *def = &iso8583_field_definitions[i-1];
        bpf_printk("Field number: %d\n",def->field_number);
        if(!iso8583_is_field_present(message, i)){
            bpf_printk("Field %d is not present\n", i);
            continue;
        }
        // Process the current field to update the offset
        __u16 length = 0;
        int read_success = 0;
        switch (def->prefix) {
            case ISO8583_PREFIX_LLVAR:
                // Read 2 characters for length
                {
                    bpf_printk("LLVAR Field number: %d prefix: %d\n",field_number,def->prefix);
                    if (data + offset + 2 > data_end) {
                        bpf_printk("Failed to read length\n");
                        return 0; // Failure
                    }
                    const char *len_str_data = (const char *)(data + offset);
                    char len_str[2];
                    len_str[0] = len_str_data[0];
                    len_str[1] = len_str_data[1];
                    
                    read_success = iso8583_strtoul(len_str, &length, 10, 2);
                    bpf_printk("LLVAR Length: %d\n", length);
                    offset += 2;
                }
                break;

            case ISO8583_PREFIX_LLLVAR:
                // Read 3 characters for length
                {
                    bpf_printk("LLLVAR Field number: %d prefix: %d\n",field_number,def->prefix);
                    char len_str[3];
                    if (bpf_probe_read_user(&len_str, sizeof(len_str), data + offset) != 0) {
                        bpf_printk("Failed to read length\n");
                        return 0; // Failure
                    }
                    read_success = iso8583_strtoul(len_str, &length, 10, 3);
                    bpf_printk("LLLVAR Length: %d\n", length);
                    offset += 3;
                }
                break;

            case ISO8583_PREFIX_FIXED:
                bpf_printk("FIXED Field number: %d prefix: %d\n",field_number,def->prefix);
                length = def->length;
                read_success = 1;
                bpf_printk("FIXED Length: %d\n", length);
                // No length prefix to read
                break;

            default:
                // Unsupported prefix type
                bpf_printk("Unsupported prefix type: %d\n", def->prefix);
                return 0; // Failure
        }

        if (!read_success) {
            // Failed to parse length
            bpf_printk("Failed to parse length\n");
            return 0; // Failure
        }
        // If we've reached the desired field, populate the out_field and return success
        if (def->field_number == field_number) {
            bpf_printk("Field %d found\n", field_number);
            out_field->type = def->type;
            out_field->length = def->length;
            
            // Define a maximum message size to ensure bounds checking
            #define MAX_MESSAGE_SIZE 1024
            if (offset + def->length > MAX_MESSAGE_SIZE) {
                bpf_printk("Field %d exceeds message size\n", field_number);
                return 0; // Failure due to out-of-bounds
            }

            // Point to the field value within the message
            out_field->value = data + offset;
            bpf_printk("Field %s finished\n", out_field->value);
            // Optionally, you can perform additional bounds checking here if necessary
            return 1; // Success
        }

        // Update the offset based on the length of the current field
        offset += length;
        bpf_printk("Offset: %d\n", offset);
        // Ensure we don't exceed the maximum message size
        if (offset > MAX_MESSAGE_SIZE) {
            bpf_printk("Field %d exceeds message size\n", field_number);
            return 0; // Failure
        }
    }

    // Field not found
    bpf_printk("Field %d not found\n", field_number);
    return 0; // Failure
}


#endif // ISO8583_H