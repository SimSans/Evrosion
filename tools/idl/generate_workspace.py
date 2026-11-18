"""Closed Internal workspace/file-v2 declarations; codecs confer no authority."""
import hashlib
import json

COMMON = {
    'schema': 1, 'maturity': 'Internal',
    'authority': 'actual_receive_route_and_authenticated_caller_fix_dataset_object_scope_and_rights_not_wire_metadata',
    'transport': {
        'control_bytes': 256, 'control_capabilities': 0,
        'max_outstanding_per_actual_incarnation_and_route': 1,
        'deadline': 'finite_absolute_monotonic_no_implicit_extension',
        'timeout': 'ends_wait_not_execution_quarantine_until_matching_actual_completion_or_proven_quiescence',
        'operation_id': 'nonzero_per_actual_requester_correlation_never_backend_global_selector',
        'actual_identity_binding': 'authenticated_endpoint_caller_incarnation_lease_operation_and_canonical_request_fingerprint_outside_wire',
        'retry': 'no_automatic_fresh_id_after_acceptance_or_uncertainty',
        'reconciliation': 'query_same_operation_then_explicit_recovery_no_unbounded_exactly_once_claim',
    },
    'outcomes': {'Completed': 0, 'Denied': 1, 'Conflict': 2, 'NotFound': 3,
                 'NoSpace': 4, 'Busy': 5, 'Unsupported': 6, 'Accepted': 7,
                 'Uncertain': 8, 'Cancelled': 9, 'Corrupt': 10, 'Stale': 11,
                 'End': 12},
}
WORKSPACE = {
    **COMMON, 'interface': 'ev.internal.workspace', 'version': 1,
    'wire': {'request_magic': 'EVWSRQ01', 'response_magic': 'EVWSRS01',
             'endianness': 'little', 'object': {'slot': 'u16_root0_or_child1_through_256', 'generation': 'u64_nonzero_nonmax'},
             'dataset': 'response_only_16_nonzero_bytes_descriptive_not_authority',
             'name': 'utf8_1_to_96_bytes_no_separator_control_dot_or_dotdot',
             'namespace_revision': 'u64_not_max_expected_for_mutations_and_paged_list',
             'methods': {'Inspect': 1, 'List': 2, 'Create': 3, 'Rename': 4,
                         'Move': 5, 'Trash': 6, 'Restore': 7, 'QueryOperation': 8},
             'list': 'one_bounded_entry_per_response_after_slot_cursor0_through_256_and_expected_namespace_revision',
             'no_wire_sector_volume_backend_global_operation_or_capability_selector': True},
    'layout': {
        'request': {'magic': [0, 8], 'opcode': [8, 1], 'request_id_u64': [16, 8],
                    'operation_id_u64': [24, 8], 'deadline_u64': [32, 8],
                    'expected_namespace_revision_u64': [40, 8], 'object': [48, 16],
                    'destination': [64, 16], 'cursor_u16': [80, 2], 'kind_u8': [82, 1],
                    'name_length_u8': [83, 1], 'name_utf8': [84, 96]},
        'response': {'magic': [0, 8], 'outcome_u8': [8, 1], 'has_entry_u8_0_or_1': [9, 1],
                     'kind_u8': [10, 1], 'entry_state_u8': [11, 1], 'name_length_u8': [12, 1],
                     'request_id_u64': [16, 8], 'operation_id_u64': [24, 8],
                     'namespace_revision_u64': [32, 8], 'dataset_id': [40, 16],
                     'object': [56, 16], 'parent': [72, 16], 'object_revision_u64': [88, 8],
                     'file_size_u32': [96, 4], 'next_cursor_u16_or_65535': [100, 2], 'name_utf8': [104, 96]},
        'object_record': {'slot_u16': [0, 2], 'generation_u64': [8, 8]},
        'reserved': 'all_unlisted_bytes_unused_variant_fields_and_name_padding_must_be_zero',
        'root_metadata': 'slot0_directory_parent_self_live_empty_name_only_no_empty_mutation_names',
        'kinds': {'File': 1, 'Directory': 2}, 'entry_states': {'Live': 1, 'Trashed': 2},
    },
    'semantics': {'directory_listing': 'metadata_not_content_authority',
                  'mutations': 'require_actual_caller_rights_for_every_source_and_destination',
                  'object_lifetime': 'rename_preserves_identity_reuse_requires_generation_and_retired_old_grants',
                  'legacy': 'file_v1_store_v2_unchanged_no_implicit_migration_or_format'},
}
FILE_V2 = {
    **COMMON, 'interface': 'ev.internal.file', 'version': 2,
    'minor': 1, 'features': {'STAGED_VERIFY': 1},
    'compatibility': {
        'minor0': 'existing_methods1_through6_and_wire_records_unchanged_legacy_commit_verification_retained',
        'staged_verify': 'requires_minor1_and_feature_bit0_before_writable_admission_no_source_constant_or_shape_substitution',
        'availability': 'authenticated_actual_Workspace_RootControl_FileContract_probe_then_separate_exact_binding_admission',
        'authority': 'support_metadata_never_grants_File_SEND_or_edit_rights',
    },
    'wire': {'request_magic': 'EVF2RQ01', 'response_magic': 'EVF2RS01', 'endianness': 'little',
             'methods': {'Read': 1, 'BeginWrite': 2, 'WriteChunk': 3,
                         'Commit': 4, 'Abort': 5, 'QueryOperation': 6, 'Verify': 7},
             'expected_revision': 'u64_not_max_exact_route_object_revision',
             'transfer_id': 'u64_nonzero_nonmax_bound_to_actual_route_requester_and_stage',
             'digest': 'sha256_of_exact_chunk_or_declared_complete_content',
             'no_wire_object_sector_volume_backend_global_operation_or_capability_selector': True},
    'layout': {
        'request': {'magic': [0, 8], 'method_u8': [8, 1], 'request_id_u64': [16, 8],
                    'operation_id_u64': [24, 8], 'deadline_u64': [32, 8],
                    'expected_revision_u64': [40, 8], 'transfer_id_u64': [48, 8],
                    'offset_u64_bounded_to_u32': [56, 8], 'chunk_length_u32': [64, 4],
                    'complete_length_u32': [68, 4], 'sha256': [72, 32]},
        'response': {'magic': [0, 8], 'outcome_u8': [8, 1], 'request_id_u64': [16, 8],
                     'operation_id_u64': [24, 8], 'revision_u64': [40, 8], 'transfer_id_u64': [48, 8],
                     'offset_u64_bounded_to_u32': [56, 8], 'chunk_length_u32': [64, 4],
                     'complete_length_u32': [68, 4], 'sha256': [72, 32]},
        'reserved': 'all_unlisted_bytes_and_unused_variant_fields_must_be_zero',
        'noncompleted': 'only_correlation_and_outcome_no_success_payload',
        'commit_confirmation': 'exact_transfer_complete_length_sha256_and_expected_revision_plus_one',
    },
    'bulk': {'max_file_bytes': 1048576, 'max_chunk_bytes': 4096,
             'kind': 'one_prebound_shared_MemoryObject_loan_separate_from_control',
             'ownership': 'private_server_snapshot_before_io_no_reuse_until_matching_completion_or_proven_quiescence',
             'read': 'server_publishes_exact_range_then_matching_response_client_verifies_digest',
             'write': 'client_publishes_exact_range_and_digest_server_verifies_private_snapshot'},
    'semantics': {'begin': 'reserve_declared_length_and_digest_without_publishing',
                  'append': 'ordered_verified_stage_chunks_never_visible_as_committed',
                  'verify': 'one_immutable_stage_chunk_at_exact_prefix_per_distinct_finite_request_full_digest_before_publication_no_deadline_renewal',
                  'commit': 'expected_revision_conflict_check_atomic_exact_content_publish_durable_receipt',
                  'saved': 'matching_durable_commit_plus_exact_revision_and_content_readback',
                  'abort': 'cooperative_cannot_undo_committed_write_or_prove_quiescence',
                  'query_completion': 'matching_scoped_operation_receipt_or_durable_stage_prefix_except_Verify_returns_exact_RAM_verified_prefix_never_automatic_retry',
                  'pending_history_miss': 'Stale_or_Corrupt_original_result_retains_Uncertain_not_loan_return_or_proof_of_nonexecution',
                  'legacy': 'separate_major_contract_file_v1_bytes_and_meaning_unchanged'},
}


def schema(source, expected):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate workspace/file contract field: ' + key)
            result[key] = value
        return result
    value = json.loads(source, object_pairs_hook=unique)
    canonical = lambda x: json.dumps(x, sort_keys=True, separators=(',', ':'), allow_nan=False)
    if canonical(value) != canonical(expected):
        raise ValueError('unsupported ' + expected['interface'] + '@' + str(expected['version']) + ' schema')
    return value


def render(source, template, expected):
    schema(source, expected)
    result = template.replace('@SHA256@', hashlib.sha256(source).hexdigest())
    if '@SHA256@' in result:
        raise ValueError('unexpanded contract template')
    return result
