"""Checked focused action-key frame; physical input provenance stays external."""
import json

EXPECTED = {
    'schema': 1, 'interface': 'ev.internal.focused-input', 'version': 1,
    'minor': 1, 'maturity': 'Internal',
    'wire': {'bytes': 8, 'magic': 'K', 'endianness': 'little',
             'keys': {'Tab': 1, 'Enter': 2, 'Escape': 3, 'Up': 4, 'Down': 5, 'Left': 6, 'Right': 7},
             'flags': {'release_known': 1, 'approval_ready': 2},
             'flags_policy': 'only_Enter_may_have_flags_approval_requires_release_known',
             'sequence': 'u32_nonzero_nonmax_monotonic_per_actual_Input_incarnation'},
    'transport': {'capabilities': 0,
                  'authority': 'none_metadata_only_actual_Input_and_focused_recipient_routes_are_external',
                  'compatibility': 'minor1_adds_Left_Right_legacy_five_key_frames_unchanged',
                  'consent': 'key_frame_alone_is_not_consent_display_provenance_or_file_authority'}}


def schema(source):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate focused input field: ' + key)
            result[key] = value
        return result
    value = json.loads(source, object_pairs_hook=unique)
    canonical = lambda x: json.dumps(x, sort_keys=True, separators=(',', ':'))
    if canonical(value) != canonical(EXPECTED):
        raise ValueError('unsupported ev.internal.focused-input@1.1 schema')
    return value
