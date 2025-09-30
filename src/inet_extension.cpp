#include "duckdb_extension.h"
#include "inet_html.h"
#include "inet_ipaddress.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Forward declare vtable
DUCKDB_EXTENSION_EXTERN

//----------------------------------------------------------------------------------------------------------------------
// HUGEINT/UHUGEINT CONVERSION HELPERS
//----------------------------------------------------------------------------------------------------------------------

static duckdb_uhugeint hugeint_to_uhugeint(duckdb_hugeint *input) {
	duckdb_uhugeint retval;
	retval.lower = input->lower;
	retval.upper = (uint64_t)input->upper;
	return retval;
}

static bool uhugeint_try_add(const duckdb_uhugeint *lhs, const duckdb_uhugeint *rhs, duckdb_uhugeint *result) {
	uint64_t new_upper = lhs->upper + rhs->upper;
	bool no_overflow = !(new_upper < lhs->upper || new_upper < rhs->upper);
	new_upper += (lhs->lower + rhs->lower) < lhs->lower;
	if (new_upper < lhs->upper || new_upper < rhs->upper) {
		no_overflow = false;
	}
	result->upper = new_upper;
	result->lower = lhs->lower + rhs->lower;
	return no_overflow;
}

static bool uhugeint_try_sub(const duckdb_uhugeint *lhs, const duckdb_uhugeint *rhs, duckdb_uhugeint *result) {
	const uint64_t new_upper = lhs->upper - rhs->upper - ((lhs->lower - rhs->lower) > lhs->lower);
	const bool no_overflow = !(new_upper > lhs->upper);

	result->lower = (lhs->lower - rhs->lower);
	result->upper = new_upper;
	return no_overflow;
}

static bool hugeint_is_positive(const duckdb_hugeint *input) {
	bool upper_bigger = input->upper > 0;
	bool upper_equal = input->upper == 0;
	bool lower_bigger = input->lower > 0;
	return upper_bigger || (upper_equal && lower_bigger);
}

static bool hugeint_is_zero(const duckdb_hugeint *input) {
	return input->upper == 0 && input->lower == 0;
}

static duckdb_hugeint hugeint_negate(const duckdb_hugeint *input) {
	duckdb_hugeint result;
	result.lower = UINT64_MAX - input->lower + 1ull;
	result.upper = -1 - input->upper + (input->lower == 0);
	return result;
}

//----------------------------------------------------------------------------------------------------------------------
// INET TYPE DEFINITION
//----------------------------------------------------------------------------------------------------------------------

static duckdb_logical_type make_inet_type() {

	duckdb_logical_type ip_type = duckdb_create_logical_type(DUCKDB_TYPE_UTINYINT);
	duckdb_logical_type addr_type = duckdb_create_logical_type(DUCKDB_TYPE_HUGEINT);
	duckdb_logical_type mask_type = duckdb_create_logical_type(DUCKDB_TYPE_USMALLINT);

	const char *child_names[] = {"ip_type", "address", "mask"};
	duckdb_logical_type child_types[] = {ip_type, addr_type, mask_type};
	duckdb_logical_type inet_type = duckdb_create_struct_type(child_types, child_names, 3);
	duckdb_logical_type_set_alias(inet_type, "INET");

	duckdb_destroy_logical_type(&ip_type);
	duckdb_destroy_logical_type(&addr_type);
	duckdb_destroy_logical_type(&mask_type);

	return inet_type;
}

//----------------------------------------------------------------------------------------------------------------------
// CAST FUNCTIONS
//----------------------------------------------------------------------------------------------------------------------

static duckdb_uhugeint from_compatible_address(duckdb_hugeint compat_addr, INET_IPAddressType addr_type) {
	duckdb_uhugeint retval;
	memcpy(&retval, &compat_addr, sizeof(duckdb_uhugeint));
	// Only flip the bit for order on IPv6 addresses. It can never be set in IPv4
	if (addr_type == INET_IP_ADDRESS_V6) {
		// The top bit is flipped when storing as the signed hugeint so that sorting
		// works correctly. Flip it back here to have a proper unsigned value.
		retval.upper ^= (((uint64_t)(1)) << 63);
	}
	return retval;
}

static duckdb_hugeint to_compatible_address(duckdb_uhugeint new_addr, INET_IPAddressType addr_type) {
	if (addr_type == INET_IP_ADDRESS_V6) {
		// Flip the top bit when storing as a signed hugeint_t so that sorting
		// works correctly.
		new_addr.upper ^= (((uint64_t)(1)) << 63);
	}
	// Don't need to flip the bit for IPv4, and the original IPv4 only
	// implementation didn't do the flipping, so maintain compatibility.
	duckdb_hugeint retval;
	memcpy(&retval, &new_addr, sizeof(duckdb_hugeint));
	return retval;
}

static bool inet_to_text_cast_impl(duckdb_function_info info, idx_t count, duckdb_vector input, duckdb_vector output) {

	duckdb_vector type_vec = duckdb_struct_vector_get_child(input, 0);
	duckdb_vector addr_vec = duckdb_struct_vector_get_child(input, 1);
	duckdb_vector mask_vec = duckdb_struct_vector_get_child(input, 2);

	const uint8_t *type_data = (uint8_t *)duckdb_vector_get_data(type_vec);
	const duckdb_hugeint *addr_data = (duckdb_hugeint *)duckdb_vector_get_data(addr_vec);
	const uint16_t *mask_data = (uint16_t *)duckdb_vector_get_data(mask_vec);

	uint64_t *source_validity = duckdb_vector_get_validity(input);
	if (source_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
	}
	uint64_t *target_validity = duckdb_vector_get_validity(output);

	INET_IPAddress inet;
	char buffer[256];

	for (idx_t i = 0; i < count; i++) {

		if (source_validity && !duckdb_validity_row_is_valid(source_validity, i)) {
			duckdb_validity_set_row_invalid(target_validity, i);
			continue;
		}

		inet.type = (INET_IPAddressType)type_data[i];
		inet.address = from_compatible_address(addr_data[i], inet.type);
		inet.mask = mask_data[i];

		size_t written = ipaddress_to_string(&inet, buffer, sizeof(buffer));

		if (written == 0) {
			duckdb_cast_function_set_row_error(info, "Could not write inet string", i, output);
			return false;
		}
		if (written >= sizeof(buffer)) {
			duckdb_cast_function_set_row_error(info, "IP address string too long", i, output);
			return false;
		}

		// Assign the string to the output vector
		duckdb_vector_assign_string_element_len(output, i, buffer, written);
	}

	return true;
}

static bool text_to_inet_cast_impl(duckdb_function_info info, idx_t count, duckdb_vector input, duckdb_vector output) {

	duckdb_vector type_vec = duckdb_struct_vector_get_child(output, 0);
	duckdb_vector addr_vec = duckdb_struct_vector_get_child(output, 1);
	duckdb_vector mask_vec = duckdb_struct_vector_get_child(output, 2);

	uint8_t *type_data = (uint8_t *)duckdb_vector_get_data(type_vec);
	duckdb_hugeint *addr_data = (duckdb_hugeint *)duckdb_vector_get_data(addr_vec);
	uint16_t *mask_data = (uint16_t *)duckdb_vector_get_data(mask_vec);

	const duckdb_cast_mode cast_mode = duckdb_cast_function_get_cast_mode(info);
	const duckdb_string_t *text_data = (duckdb_string_t *)duckdb_vector_get_data(input);

	uint64_t *source_validity = duckdb_vector_get_validity(input);
	if (source_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
		duckdb_vector_ensure_validity_writable(type_vec);
		duckdb_vector_ensure_validity_writable(addr_vec);
		duckdb_vector_ensure_validity_writable(mask_vec);
	}

	uint64_t *target_validity = duckdb_vector_get_validity(output);
	uint64_t *type_validity = duckdb_vector_get_validity(type_vec);
	uint64_t *addr_validity = duckdb_vector_get_validity(addr_vec);
	uint64_t *mask_validity = duckdb_vector_get_validity(mask_vec);

	bool success = true;

	for (idx_t i = 0; i < count; i++) {

		if (source_validity && !duckdb_validity_row_is_valid(source_validity, i)) {
			duckdb_validity_set_row_invalid(target_validity, i);
			duckdb_validity_set_row_invalid(type_validity, i);
			duckdb_validity_set_row_invalid(addr_validity, i);
			duckdb_validity_set_row_invalid(mask_validity, i);
			continue;
		}

		duckdb_string_t text = text_data[i];
		const char *data = duckdb_string_t_data(&text);
		size_t size = duckdb_string_t_length(text);

		char *error_message = "Failed to parse INET";
		INET_IPAddress inet = ipaddress_from_string(data, size, &error_message);

		// Did we succeed in parsing?
		if (inet.type == INET_IP_ADDRESS_INVALID) {
			// Set error message and null the output row (recursively)
			duckdb_cast_function_set_row_error(info, error_message, i, output);

			if (cast_mode != DUCKDB_CAST_TRY) {
				return false;
			}

			// Try cast, continue with the next row
			success = false;
			continue;
		}

		type_data[i] = (uint8_t)inet.type;
		addr_data[i] = to_compatible_address(inet.address, inet.type);
		mask_data[i] = inet.mask;
	}

	return success;
}

//----------------------------------------------------------------------------------------------------------------------
// SCALAR FUNCTIONS
//----------------------------------------------------------------------------------------------------------------------
static void host_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {

	idx_t count = duckdb_data_chunk_get_size(input);

	duckdb_vector inet_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_vector type_vec = duckdb_struct_vector_get_child(inet_vec, 0);
	duckdb_vector addr_vec = duckdb_struct_vector_get_child(inet_vec, 1);

	const uint8_t *type_data = (uint8_t *)duckdb_vector_get_data(type_vec);
	const duckdb_hugeint *addr_data = (duckdb_hugeint *)duckdb_vector_get_data(addr_vec);

	uint64_t *source_validity = duckdb_vector_get_validity(inet_vec);
	if (source_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
	}
	uint64_t *target_validity = duckdb_vector_get_validity(output);

	INET_IPAddress inet;
	char buffer[256];

	for (idx_t i = 0; i < count; i++) {

		if (source_validity && !duckdb_validity_row_is_valid(source_validity, i)) {
			duckdb_validity_set_row_invalid(target_validity, i);
			continue;
		}

		inet.type = (INET_IPAddressType)type_data[i];
		inet.address = from_compatible_address(addr_data[i], inet.type);
		inet.mask = inet.type == INET_IP_ADDRESS_V4 ? 32 : 128;

		size_t written = ipaddress_to_string(&inet, buffer, sizeof(buffer));

		if (written == 0) {
			duckdb_scalar_function_set_error(info, "Could not write inet string");
			return;
		}
		if (written >= sizeof(buffer)) {
			duckdb_scalar_function_set_error(info, "Could not write string");
			return;
		}

		// Assign the string to the output vector
		duckdb_vector_assign_string_element_len(output, i, buffer, written);
	}
}

static void family_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {

	idx_t count = duckdb_data_chunk_get_size(input);

	duckdb_vector inet_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_vector type_vec = duckdb_struct_vector_get_child(inet_vec, 0);

	uint8_t *type_data = (uint8_t *)duckdb_vector_get_data(type_vec);
	uint8_t *output_data = (uint8_t *)duckdb_vector_get_data(output);

	uint64_t *source_validity = duckdb_vector_get_validity(inet_vec);
	if (source_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
	}
	uint64_t *target_validity = duckdb_vector_get_validity(output);

	for (idx_t i = 0; i < count; i++) {

		if (source_validity && !duckdb_validity_row_is_valid(source_validity, i)) {
			duckdb_validity_set_row_invalid(target_validity, i);
			continue;
		}

		switch ((INET_IPAddressType)type_data[i]) {
		case INET_IP_ADDRESS_V4:
			output_data[i] = 4;
			break;
		case INET_IP_ADDRESS_V6:
			output_data[i] = 6;
			break;
		default:
			duckdb_scalar_function_set_error(info, "Invalid IP address type");
			return;
		}
	}
}

static void generic_inet_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output,
                                       INET_IPAddress (*func)(const INET_IPAddress *ip)) {
	idx_t count = duckdb_data_chunk_get_size(input);

	duckdb_vector inet_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_vector type_vec = duckdb_struct_vector_get_child(inet_vec, 0);
	duckdb_vector addr_vec = duckdb_struct_vector_get_child(inet_vec, 1);
	duckdb_vector mask_vec = duckdb_struct_vector_get_child(inet_vec, 2);

	const uint8_t *type_data = (uint8_t *)duckdb_vector_get_data(type_vec);
	const duckdb_hugeint *addr_data = (duckdb_hugeint *)duckdb_vector_get_data(addr_vec);
	const uint16_t *mask_data = (uint16_t *)duckdb_vector_get_data(mask_vec);

	duckdb_vector out_type_vec = duckdb_struct_vector_get_child(output, 0);
	duckdb_vector out_addr_vec = duckdb_struct_vector_get_child(output, 1);
	duckdb_vector out_mask_vec = duckdb_struct_vector_get_child(output, 2);

	uint8_t *out_type_data = (uint8_t *)duckdb_vector_get_data(out_type_vec);
	duckdb_hugeint *out_addr_data = (duckdb_hugeint *)duckdb_vector_get_data(out_addr_vec);
	uint16_t *out_mask_data = (uint16_t *)duckdb_vector_get_data(out_mask_vec);

	uint64_t *source_validity = duckdb_vector_get_validity(inet_vec);
	if (source_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
		duckdb_vector_ensure_validity_writable(out_type_vec);
		duckdb_vector_ensure_validity_writable(out_addr_vec);
		duckdb_vector_ensure_validity_writable(out_mask_vec);
	}
	uint64_t *target_validity = duckdb_vector_get_validity(output);
	uint64_t *type_validity = duckdb_vector_get_validity(out_type_vec);
	uint64_t *addr_validity = duckdb_vector_get_validity(out_addr_vec);
	uint64_t *mask_validity = duckdb_vector_get_validity(out_mask_vec);

	for (idx_t i = 0; i < count; i++) {

		if (source_validity && !duckdb_validity_row_is_valid(source_validity, i)) {
			duckdb_validity_set_row_invalid(target_validity, i);
			duckdb_validity_set_row_invalid(type_validity, i);
			duckdb_validity_set_row_invalid(addr_validity, i);
			duckdb_validity_set_row_invalid(mask_validity, i);
			continue;
		}

		INET_IPAddress old_inet = {0};
		old_inet.type = (INET_IPAddressType)type_data[i];
		old_inet.address = from_compatible_address(addr_data[i], old_inet.type);
		old_inet.mask = mask_data[i];

		// Apply the function
		INET_IPAddress new_inet = func(&old_inet);

		out_type_data[i] = (uint8_t)new_inet.type;
		out_addr_data[i] = to_compatible_address(new_inet.address, new_inet.type);
		out_mask_data[i] = new_inet.mask;
	}
}

static void netmask_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	generic_inet_function_impl(info, input, output, ipaddress_netmask);
}

static void network_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	generic_inet_function_impl(info, input, output, ipaddress_network);
}

static void broadcast_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	generic_inet_function_impl(info, input, output, ipaddress_broadcast);
}

static void arithmetic_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output,
                                     bool is_add) {
	idx_t count = duckdb_data_chunk_get_size(input);

	duckdb_vector source_inet_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_vector number_vec = duckdb_data_chunk_get_vector(input, 1);

	duckdb_vector source_type_vec = duckdb_struct_vector_get_child(source_inet_vec, 0);
	duckdb_vector source_addr_vec = duckdb_struct_vector_get_child(source_inet_vec, 1);
	duckdb_vector source_mask_vec = duckdb_struct_vector_get_child(source_inet_vec, 2);

	duckdb_vector target_type_vec = duckdb_struct_vector_get_child(output, 0);
	duckdb_vector target_addr_vec = duckdb_struct_vector_get_child(output, 1);
	duckdb_vector target_mask_vec = duckdb_struct_vector_get_child(output, 2);

	const uint8_t *source_type_data = (uint8_t *)duckdb_vector_get_data(source_type_vec);
	const duckdb_hugeint *source_addr_data = (duckdb_hugeint *)duckdb_vector_get_data(source_addr_vec);
	const uint16_t *source_mask_data = (uint16_t *)duckdb_vector_get_data(source_mask_vec);

	duckdb_hugeint *number_data = (duckdb_hugeint *)duckdb_vector_get_data(number_vec);

	uint8_t *target_type_data = (uint8_t *)duckdb_vector_get_data(target_type_vec);
	duckdb_hugeint *target_addr_data = (duckdb_hugeint *)duckdb_vector_get_data(target_addr_vec);
	uint16_t *target_mask_data = (uint16_t *)duckdb_vector_get_data(target_mask_vec);

	uint64_t *source_validity = duckdb_vector_get_validity(source_inet_vec);
	uint64_t *number_validity = duckdb_vector_get_validity(number_vec);
	if (source_validity || number_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
		duckdb_vector_ensure_validity_writable(target_type_vec);
		duckdb_vector_ensure_validity_writable(target_addr_vec);
		duckdb_vector_ensure_validity_writable(target_mask_vec);
	}

	uint64_t *target_validity = duckdb_vector_get_validity(output);
	uint64_t *target_type_validity = duckdb_vector_get_validity(target_type_vec);
	uint64_t *target_addr_validity = duckdb_vector_get_validity(target_addr_vec);
	uint64_t *target_mask_validity = duckdb_vector_get_validity(target_mask_vec);

	for (idx_t i = 0; i < count; i++) {
		if ((source_validity && !duckdb_validity_row_is_valid(source_validity, i)) ||
		    (number_validity && !duckdb_validity_row_is_valid(number_validity, i))) {
			duckdb_validity_set_row_invalid(target_validity, i);
			duckdb_validity_set_row_invalid(target_type_validity, i);
			duckdb_validity_set_row_invalid(target_addr_validity, i);
			duckdb_validity_set_row_invalid(target_mask_validity, i);
			continue;
		}

		duckdb_hugeint number;
		if (is_add) {
			// +
			number = number_data[i];
		} else {
			// -
			number = hugeint_negate(&number_data[i]);
		}

		if (hugeint_is_zero(&number)) {
			// Nothing to add, pass on the data
			target_type_data[i] = source_type_data[i];
			target_addr_data[i] = source_addr_data[i];
			target_mask_data[i] = source_mask_data[i];
			continue;
		}

		duckdb_uhugeint address_in =
		    from_compatible_address(source_addr_data[i], (INET_IPAddressType)source_type_data[i]);
		duckdb_uhugeint address_out = address_in;

		if (hugeint_is_positive(&number)) {
			duckdb_uhugeint unsigned_number = hugeint_to_uhugeint(&number);
			if (!uhugeint_try_add(&address_in, &unsigned_number, &address_out)) {
				duckdb_scalar_function_set_error(info, "Out of Range Error: Overflow in addition");
				return;
			}
		} else {
			duckdb_hugeint negated_number = hugeint_negate(&number);
			duckdb_uhugeint unsigned_number = hugeint_to_uhugeint(&negated_number);
			if (!uhugeint_try_sub(&address_in, &unsigned_number, &address_out)) {
				duckdb_scalar_function_set_error(info, "Out of Range Error: Overflow in subtraction");
				return;
			}
		}

		if (source_type_data[i] == INET_IP_ADDRESS_V4) {
			// Check if overflow ipv4
			if (address_out.lower >= 0xffffffff) {
				duckdb_scalar_function_set_error(info, "Out of Range Error: Cannot add 1");
				return;
			}
		}

		target_type_data[i] = source_type_data[i];
		target_addr_data[i] = to_compatible_address(address_out, (INET_IPAddressType)source_type_data[i]);
		target_mask_data[i] = source_mask_data[i];
	}
}

static void add_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	arithmetic_function_impl(info, input, output, true);
}

static void sub_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	arithmetic_function_impl(info, input, output, false);
}

static void contains_impl(duckdb_vector lhs_inet_vec, duckdb_vector rhs_inet_vec, idx_t count, duckdb_vector output) {

	duckdb_vector lhs_type_vec = duckdb_struct_vector_get_child(lhs_inet_vec, 0);
	duckdb_vector lhs_addr_vec = duckdb_struct_vector_get_child(lhs_inet_vec, 1);
	duckdb_vector lhs_mask_vec = duckdb_struct_vector_get_child(lhs_inet_vec, 2);

	duckdb_vector rhs_type_vec = duckdb_struct_vector_get_child(rhs_inet_vec, 0);
	duckdb_vector rhs_addr_vec = duckdb_struct_vector_get_child(rhs_inet_vec, 1);
	duckdb_vector rhs_mask_vec = duckdb_struct_vector_get_child(rhs_inet_vec, 2);

	const uint8_t *lhs_type_data = (uint8_t *)duckdb_vector_get_data(lhs_type_vec);
	const duckdb_hugeint *lhs_addr_data = (duckdb_hugeint *)duckdb_vector_get_data(lhs_addr_vec);
	const uint16_t *lhs_mask_data = (uint16_t *)duckdb_vector_get_data(lhs_mask_vec);

	const uint8_t *rhs_type_data = (uint8_t *)duckdb_vector_get_data(rhs_type_vec);
	const duckdb_hugeint *rhs_addr_data = (duckdb_hugeint *)duckdb_vector_get_data(rhs_addr_vec);
	const uint16_t *rhs_mask_data = (uint16_t *)duckdb_vector_get_data(rhs_mask_vec);

	bool *output_data = (bool *)duckdb_vector_get_data(output);

	uint64_t *left_validity = duckdb_vector_get_validity(lhs_inet_vec);
	uint64_t *right_validity = duckdb_vector_get_validity(rhs_inet_vec);
	if (left_validity || right_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
	}
	uint64_t *target_validity = duckdb_vector_get_validity(output);

	for (idx_t i = 0; i < count; i++) {
		if ((left_validity && !duckdb_validity_row_is_valid(left_validity, i)) ||
		    (right_validity && !duckdb_validity_row_is_valid(right_validity, i))) {
			duckdb_validity_set_row_invalid(target_validity, i);
			continue;
		}

		INET_IPAddress lhs_inet;
		lhs_inet.type = (INET_IPAddressType)lhs_type_data[i];
		lhs_inet.address = from_compatible_address(lhs_addr_data[i], lhs_inet.type);
		lhs_inet.mask = lhs_mask_data[i];

		INET_IPAddress rhs_inet;
		rhs_inet.type = (INET_IPAddressType)rhs_type_data[i];
		rhs_inet.address = from_compatible_address(rhs_addr_data[i], rhs_inet.type);
		rhs_inet.mask = rhs_mask_data[i];

		INET_IPAddress lhs_network = ipaddress_network(&lhs_inet);
		INET_IPAddress lhs_broadcast = ipaddress_broadcast(&lhs_inet);

		INET_IPAddress rhs_network = ipaddress_network(&rhs_inet);
		INET_IPAddress rhs_broadcast = ipaddress_broadcast(&rhs_inet);

		// Set the output
		const bool network_in_lower = lhs_network.address.lower >= rhs_network.address.lower;
		const bool network_in_upper = lhs_network.address.upper >= rhs_network.address.upper;
		const bool broadcast_in_lower = lhs_broadcast.address.lower <= rhs_broadcast.address.lower;
		const bool broadcast_in_upper = lhs_broadcast.address.upper <= rhs_broadcast.address.upper;

		output_data[i] = network_in_lower && network_in_upper && broadcast_in_lower && broadcast_in_upper;
	}
}

static void contains_left_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	idx_t count = duckdb_data_chunk_get_size(input);
	duckdb_vector lhs_inet_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_vector rhs_inet_vec = duckdb_data_chunk_get_vector(input, 1);
	contains_impl(lhs_inet_vec, rhs_inet_vec, count, output);
}

static void contains_right_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	idx_t count = duckdb_data_chunk_get_size(input);
	duckdb_vector lhs_inet_vec = duckdb_data_chunk_get_vector(input, 1);
	duckdb_vector rhs_inet_vec = duckdb_data_chunk_get_vector(input, 0);
	contains_impl(lhs_inet_vec, rhs_inet_vec, count, output);
}

//----------------------------------------------------------------------------------------------------------------------
// HTML ESCAPE
//----------------------------------------------------------------------------------------------------------------------

static void escape_html(duckdb_function_info info, duckdb_vector output, idx_t index, const char *input_data,
                        idx_t input_size, bool input_quote) {

	const idx_t QUOTE_SZ = 1;
	const idx_t AMPERSAND_SZ = 5;
	const idx_t ANGLE_BRACKET_SZ = 4;
	const idx_t TRANSLATED_QUOTE_SZ = 6; // e.g. \" is translated to &quot;, \' is translated to &#x27;

	size_t result_size = 0;
	for (idx_t j = 0; j < input_size; j++) {
		switch (input_data[j]) {
		case '&':
			result_size += AMPERSAND_SZ;
			break;
		case '<':
		case '>':
			result_size += ANGLE_BRACKET_SZ;
			break;
		case '\"':
		case '\'':
			result_size += input_quote ? TRANSLATED_QUOTE_SZ : QUOTE_SZ;
			break;
		default:
			result_size++;
		}
	}

	// Ugh, malloc a new string...
	char *result_data = (char *)duckdb_malloc(result_size);
	if (!result_data) {
		duckdb_scalar_function_set_error(info, "Failed to allocate memory for html escape");
		return;
	}

	size_t pos = 0;
	for (idx_t j = 0; j < input_size; j++) {
		switch (input_data[j]) {
		case '&':
			memcpy(result_data + pos, "&amp;", AMPERSAND_SZ);
			pos += AMPERSAND_SZ;
			break;
		case '<':
			memcpy(result_data + pos, "&lt;", ANGLE_BRACKET_SZ);
			pos += ANGLE_BRACKET_SZ;
			break;
		case '>':
			memcpy(result_data + pos, "&gt;", ANGLE_BRACKET_SZ);
			pos += ANGLE_BRACKET_SZ;
			break;
		case '"':
			if (input_quote) {
				memcpy(result_data + pos, "&quot;", TRANSLATED_QUOTE_SZ);
				pos += TRANSLATED_QUOTE_SZ;
			} else {
				result_data[pos++] = input_data[j];
			}
			break;
		case '\'':
			if (input_quote) {
				memcpy(result_data + pos, "&#x27;", TRANSLATED_QUOTE_SZ);
				pos += TRANSLATED_QUOTE_SZ;
			} else {
				result_data[pos++] = input_data[j];
			}
			break;
		default:
			result_data[pos++] = input_data[j];
		}
	}

	// Assign the string to the output vector
	duckdb_vector_assign_string_element_len(output, index, result_data, result_size);

	// Free the temporary string again
	duckdb_free(result_data);
}

static void html_escape_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {

	idx_t count = duckdb_data_chunk_get_size(input);

	duckdb_vector html_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_string_t *html_data = (duckdb_string_t *)duckdb_vector_get_data(html_vec);

	uint64_t *html_validity = duckdb_vector_get_validity(html_vec);
	if (html_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
	}
	uint64_t *result_validity = duckdb_vector_get_validity(output);

	for (idx_t i = 0; i < count; i++) {
		if (html_validity && !duckdb_validity_row_is_valid(html_validity, i)) {
			duckdb_validity_set_row_invalid(result_validity, i);
			continue;
		}

		const char *input_data = duckdb_string_t_data(&html_data[i]);
		size_t input_size = duckdb_string_t_length(html_data[i]);

		escape_html(info, output, i, input_data, input_size, true);
	}
}

static void html_escape_quoute_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {

	idx_t count = duckdb_data_chunk_get_size(input);

	duckdb_vector html_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_vector quote_vec = duckdb_data_chunk_get_vector(input, 1);

	duckdb_string_t *html_data = (duckdb_string_t *)duckdb_vector_get_data(html_vec);
	bool *quote_data = (bool *)duckdb_vector_get_data(quote_vec);

	uint64_t *html_validity = duckdb_vector_get_validity(html_vec);
	uint64_t *quote_validity = duckdb_vector_get_validity(quote_vec);

	if (html_validity || quote_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
	}
	uint64_t *result_validity = duckdb_vector_get_validity(output);

	for (idx_t i = 0; i < count; i++) {
		if ((html_validity && !duckdb_validity_row_is_valid(html_validity, i)) ||
		    (quote_validity && !duckdb_validity_row_is_valid(quote_validity, i))) {
			duckdb_validity_set_row_invalid(result_validity, i);
			continue;
		}

		const char *input_data = duckdb_string_t_data(&html_data[i]);
		size_t input_size = duckdb_string_t_length(html_data[i]);
		bool input_quote = quote_data[i];

		escape_html(info, output, i, input_data, input_size, input_quote);
	}
}

static void html_unescape_function_impl(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {

	idx_t count = duckdb_data_chunk_get_size(input);

	duckdb_vector html_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_string_t *html_data = (duckdb_string_t *)duckdb_vector_get_data(html_vec);

	uint64_t *html_validity = duckdb_vector_get_validity(html_vec);
	if (html_validity) {
		// We might have NULL values, ensure the validity mask is writable
		duckdb_vector_ensure_validity_writable(output);
	}
	uint64_t *result_validity = duckdb_vector_get_validity(output);

	for (idx_t i = 0; i < count; i++) {
		if (html_validity && !duckdb_validity_row_is_valid(html_validity, i)) {
			duckdb_validity_set_row_invalid(result_validity, i);
			continue;
		}

		const char *input_data = duckdb_string_t_data(&html_data[i]);
		size_t input_size = duckdb_string_t_length(html_data[i]);

		// Compute the result size
		size_t result_size = inet_html_unescaped_get_required_size(input_data, input_size);

		// Allocate the result string
		char *result_data = (char *)duckdb_malloc(result_size);
		if (!result_data) {
			duckdb_scalar_function_set_error(info, "Failed to allocate memory for html unescape");
			return;
		}

		// Now parse again and fill the result string with the unescaped data
		inet_html_unescape(input_data, input_size, result_data, result_size);

		// Assign the string to the output vector
		duckdb_vector_assign_string_element_len(output, i, result_data, result_size);

		// Free the temporary string again
		duckdb_free(result_data);
	}
}

//----------------------------------------------------------------------------------------------------------------------
// EXTENSION ENTRY
//----------------------------------------------------------------------------------------------------------------------

DUCKDB_EXTENSION_ENTRYPOINT(duckdb_connection connection, duckdb_extension_info info,
                            struct duckdb_extension_access *access) {

	bool success = true;

	duckdb_logical_type inet_type = make_inet_type();
	duckdb_logical_type text_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);
	duckdb_logical_type bool_type = duckdb_create_logical_type(DUCKDB_TYPE_BOOLEAN);
	duckdb_logical_type utinyint_type = duckdb_create_logical_type(DUCKDB_TYPE_UTINYINT);
	duckdb_logical_type hugeint_type = duckdb_create_logical_type(DUCKDB_TYPE_HUGEINT);

	// Register the type
	success = duckdb_register_logical_type(connection, inet_type, NULL) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register INET type");
		goto cleanup;
	}

	// Register cast functions
	duckdb_cast_function inet_to_text = duckdb_create_cast_function();
	duckdb_cast_function_set_implicit_cast_cost(inet_to_text, -1);
	duckdb_cast_function_set_source_type(inet_to_text, inet_type);
	duckdb_cast_function_set_target_type(inet_to_text, text_type);
	duckdb_cast_function_set_function(inet_to_text, inet_to_text_cast_impl);

	success = duckdb_register_cast_function(connection, inet_to_text) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register INET to TEXT cast function");
		goto cleanup;
	}

	duckdb_cast_function text_to_inet = duckdb_create_cast_function();
	duckdb_cast_function_set_implicit_cast_cost(text_to_inet, -1);
	duckdb_cast_function_set_source_type(text_to_inet, text_type);
	duckdb_cast_function_set_target_type(text_to_inet, inet_type);
	duckdb_cast_function_set_function(text_to_inet, text_to_inet_cast_impl);

	success = duckdb_register_cast_function(connection, text_to_inet) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register TEXT to INET cast function");
		goto cleanup;
	}

	// Scalar functions
	duckdb_scalar_function host_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(host_function, "host");
	duckdb_scalar_function_add_parameter(host_function, inet_type);
	duckdb_scalar_function_set_return_type(host_function, text_type);
	duckdb_scalar_function_set_function(host_function, host_function_impl);
	success = duckdb_register_scalar_function(connection, host_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register host function");
		goto cleanup;
	}

	duckdb_scalar_function family_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(family_function, "family");
	duckdb_scalar_function_add_parameter(family_function, inet_type);
	duckdb_scalar_function_set_return_type(family_function, utinyint_type);
	duckdb_scalar_function_set_function(family_function, family_function_impl);
	success = duckdb_register_scalar_function(connection, family_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register family function");
		goto cleanup;
	}

	duckdb_scalar_function netmask_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(netmask_function, "netmask");
	duckdb_scalar_function_add_parameter(netmask_function, inet_type);
	duckdb_scalar_function_set_return_type(netmask_function, inet_type);
	duckdb_scalar_function_set_function(netmask_function, netmask_function_impl);
	success = duckdb_register_scalar_function(connection, netmask_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register net mask function");
		goto cleanup;
	}

	duckdb_scalar_function network_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(network_function, "network");
	duckdb_scalar_function_add_parameter(network_function, inet_type);
	duckdb_scalar_function_set_return_type(network_function, inet_type);
	duckdb_scalar_function_set_function(network_function, network_function_impl);
	success = duckdb_register_scalar_function(connection, network_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register network function");
		goto cleanup;
	}

	duckdb_scalar_function broadcast_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(broadcast_function, "broadcast");
	duckdb_scalar_function_add_parameter(broadcast_function, inet_type);
	duckdb_scalar_function_set_return_type(broadcast_function, inet_type);
	duckdb_scalar_function_set_function(broadcast_function, broadcast_function_impl);
	success = duckdb_register_scalar_function(connection, broadcast_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register broadcast function");
		goto cleanup;
	}

	duckdb_scalar_function add_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(add_function, "+");
	duckdb_scalar_function_add_parameter(add_function, inet_type);
	duckdb_scalar_function_add_parameter(add_function, hugeint_type);
	duckdb_scalar_function_set_return_type(add_function, inet_type);
	duckdb_scalar_function_set_function(add_function, add_function_impl);
	success = duckdb_register_scalar_function(connection, add_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register + function");
		goto cleanup;
	}

	duckdb_scalar_function sub_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(sub_function, "-");
	duckdb_scalar_function_add_parameter(sub_function, inet_type);
	duckdb_scalar_function_add_parameter(sub_function, hugeint_type);
	duckdb_scalar_function_set_return_type(sub_function, inet_type);
	duckdb_scalar_function_set_function(sub_function, sub_function_impl);
	success = duckdb_register_scalar_function(connection, sub_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register - function");
		goto cleanup;
	}

	duckdb_scalar_function contains_left_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(contains_left_function, "<<=");
	duckdb_scalar_function_add_parameter(contains_left_function, inet_type);
	duckdb_scalar_function_add_parameter(contains_left_function, inet_type);
	duckdb_scalar_function_set_return_type(contains_left_function, bool_type);
	duckdb_scalar_function_set_function(contains_left_function, contains_left_function_impl);
	success = duckdb_register_scalar_function(connection, contains_left_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register <<= function");
		goto cleanup;
	}
	duckdb_scalar_function_set_name(contains_left_function, "subnet_contained_by_or_equals");
	success = duckdb_register_scalar_function(connection, contains_left_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register subnet_contained_by_or_equals function");
		goto cleanup;
	}

	duckdb_scalar_function contains_right_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(contains_right_function, ">>=");
	duckdb_scalar_function_add_parameter(contains_right_function, inet_type);
	duckdb_scalar_function_add_parameter(contains_right_function, inet_type);
	duckdb_scalar_function_set_return_type(contains_right_function, bool_type);
	duckdb_scalar_function_set_function(contains_right_function, contains_right_function_impl);
	success = duckdb_register_scalar_function(connection, contains_right_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register >>= function");
		goto cleanup;
	}
	duckdb_scalar_function_set_name(contains_right_function, "subnet_contains_or_equals");
	success = duckdb_register_scalar_function(connection, contains_right_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register subnet_contains_or_equals function");
		goto cleanup;
	}

	duckdb_scalar_function_set html_escape_function_set = duckdb_create_scalar_function_set("html_escape");
	duckdb_scalar_function html_escape_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(html_escape_function, "html_escape");
	duckdb_scalar_function_set_return_type(html_escape_function, text_type);
	duckdb_scalar_function_add_parameter(html_escape_function, text_type);
	duckdb_scalar_function_set_function(html_escape_function, html_escape_function_impl);
	duckdb_add_scalar_function_to_set(html_escape_function_set, html_escape_function);

	duckdb_scalar_function html_escape_quote_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(html_escape_quote_function, "html_escape");
	duckdb_scalar_function_set_return_type(html_escape_quote_function, text_type);
	duckdb_scalar_function_add_parameter(html_escape_quote_function, text_type);
	duckdb_scalar_function_add_parameter(html_escape_quote_function, bool_type);
	duckdb_scalar_function_set_function(html_escape_quote_function, html_escape_quoute_function_impl);
	duckdb_add_scalar_function_to_set(html_escape_function_set, html_escape_quote_function);

	success = duckdb_register_scalar_function_set(connection, html_escape_function_set) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register html_escape function");
		goto cleanup;
	}

	duckdb_scalar_function html_unescape_function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(html_unescape_function, "html_unescape");
	duckdb_scalar_function_set_return_type(html_unescape_function, text_type);
	duckdb_scalar_function_add_parameter(html_unescape_function, text_type);
	duckdb_scalar_function_set_function(html_unescape_function, html_unescape_function_impl);
	success = duckdb_register_scalar_function(connection, html_unescape_function) == DuckDBSuccess;
	if (!success) {
		access->set_error(info, "Failed to register html_unescape function");
		goto cleanup;
	}

cleanup: // Cleanup

	duckdb_destroy_logical_type(&inet_type);
	duckdb_destroy_logical_type(&text_type);
	duckdb_destroy_logical_type(&bool_type);
	duckdb_destroy_logical_type(&utinyint_type);
	duckdb_destroy_logical_type(&hugeint_type);

	duckdb_destroy_cast_function(&text_to_inet);
	duckdb_destroy_cast_function(&inet_to_text);

	duckdb_destroy_scalar_function(&host_function);
	duckdb_destroy_scalar_function(&family_function);
	duckdb_destroy_scalar_function(&netmask_function);
	duckdb_destroy_scalar_function(&network_function);
	duckdb_destroy_scalar_function(&broadcast_function);
	duckdb_destroy_scalar_function(&add_function);
	duckdb_destroy_scalar_function(&sub_function);
	duckdb_destroy_scalar_function(&contains_left_function);
	duckdb_destroy_scalar_function(&contains_right_function);

	duckdb_destroy_scalar_function(&html_escape_function);
	duckdb_destroy_scalar_function(&html_escape_quote_function);
	duckdb_destroy_scalar_function_set(&html_escape_function_set);
	duckdb_destroy_scalar_function(&html_unescape_function);

	if (!success) {
		return false;
	}

	return true;
}
