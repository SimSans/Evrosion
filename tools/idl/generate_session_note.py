"""Closed nonce/bulk session-note schema. No legacy private-data reinterpretation."""
import json

EXPECTED = {'schema': 1,
 'interface': 'ev.app.session-note',
 'version': 1,
 'maturity': 'Internal',
 'wire': {'bytes': 8,
          'magic': 'NT',
          'endianness': 'little',
          'nonce': 'u32_nonzero_nonmax_strictly_increasing_per_actual_incarnation',
          'requests': {'Read': 1, 'Write': 2},
          'replies': {'Read': 3, 'Written': 4},
          'refusal_base': 128,
          'refusals': {'Denied': 1, 'Malformed': 2, 'Busy': 3, 'Stale': 4, 'Storage': 5, 'Recovery': 6}},
 'bulk': {'bytes': 256,
          'object': 'prebound_shared_MemoryObject',
          'codec': 'NoteDataEnvelope_v2_epoch2',
          'note': 'at_most_128_printable_ASCII_bytes_valid_UTF8_subset',
          'write': 'proposed_next_revision_expected_previous_equals_counter_minus_one',
          'response': 'exact_fresh_read_or_committed_readback_envelope',
          'checksum': 'corruption_detection_not_authentication'},
 'transport': {'mode': 'bounded_async',
               'max_capabilities': 0,
               'max_outstanding_per_actual_incarnation': 1,
               'deadline': 'finite_absolute_monotonic_fixed_for_each_exchange_outside_wire',
               'retry': 'only_definitely_unaccepted_WOULD_BLOCK_same_request_never_after_acceptance',
               'completion': 'matching_authenticated_Root_ACK_and_validated_bulk_before_page_reuse',
               'uncertainty': 'timeout_malformed_ACK_storage_or_recovery_quarantines_until_verified_quiescence',
               'shared_page': 'serialize_File_RPC_and_note_exchange_no_reuse_until_ACK_or_actual_quiescence',
               'authority': 'actual_current_Root_App_sender_namespace_package_and_incarnation_outside_wire'}}

def schema(source):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate schema field: ' + key)
            result[key] = value
        return result
    value = json.loads(source, object_pairs_hook=unique)
    canonical = lambda value: json.dumps(value,sort_keys=True,separators=(',', ':'))
    if canonical(value) != canonical(EXPECTED):
        raise ValueError('unsupported ev.app.session-note@1 schema; no declarations were generated')
    return value
