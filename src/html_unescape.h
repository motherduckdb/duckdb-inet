#pragma once

#include <stddef.h>
#include <stdint.h>

struct html_named_entity { char *name; uint32_t codepoints[2]; };
struct html_named_entity * html_named_entity_lookup (const char* str, size_t len);

size_t html_unescaped_get_required_size(const char* input_data, size_t input_size);
void html_unescape(const char* input_data, size_t input_size, char* result_data, size_t result_size);
