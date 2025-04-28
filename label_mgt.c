/*
 * Copyright (c) 2025, Spanidea. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 **/

#include <stdint.h>
#include <stdio.h>

#define LABEL_MIN 16
#define LABEL_MAX 65535
#define LABEL_COUNT (LABEL_MAX - LABEL_MIN + 1)
#define BITMAP_WORDS ((LABEL_COUNT + 31) / 32)

static uint32_t label_bitmap[BITMAP_WORDS] = {0};

// Allocate the first available label
uint32_t  allocate_label (void) {
    for (int i = 0; i < LABEL_COUNT; ++i) {
        uint32_t word_index = i / 32;
        uint32_t bit_index = i % 32;

        if (!(label_bitmap[word_index] & ((uint32_t)1 << bit_index))) {
            // Mark as allocated
            label_bitmap[word_index] |= ((uint32_t)1 << bit_index);
            return LABEL_MIN + i;
        }
    }
    return -1; // No labels available
}


// Free a previously allocated label
uint8_t free_label (uint32_t label) {
    if (label < LABEL_MIN || label > LABEL_MAX)
        return 0;

    uint32_t index = label - LABEL_MIN;
    uint32_t word_index = index / 32;
    uint32_t bit_index = index % 32;

    label_bitmap[word_index] &= ~((uint32_t)1 << bit_index);
    return 1;
}


