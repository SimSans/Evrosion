"""Pure adversaries for physical-evidence readers; no build/VM claims."""
import hashlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import persistence as v


def file_line():
    b=bytearray(256);b[:8]=b'EVFC\x01\0\x01\0'
    for i,n in enumerate([1,1,11,1,2,2,1,1,1,1,1,1]):b[8+i*8:16+i*8]=n.to_bytes(8,'little')
    b[104:136]=hashlib.sha256(b'file-content-B').digest()
    return ('EVROSION_M3_FILE status=PASS scope=object phase=write calls=52 blocks=52 wakes=52 replies=52 '
            'outer=11 backend=41 nested=18 startup=23 pre_delivery=0 delivered_nested=18 max_pending=2 '
            'mutations=11 snapshots=1 authority_denied=1 block_denied=1 unbound_denied=1 bindings=2 mapped=4 '
            'frames=true metadata=true guards=true report='+b.hex()+'\n')


class ExtendedTests(unittest.TestCase):
    def test_actual_file_serial_requires_all_ownership_nesting_and_counter_outcomes(self):
        good=file_line();f,n=v.file_report(good)
        self.assertEqual(n['calls'],52)
        for before,after in [('blocks=52','blocks=51'),('outer=11','outer=10'),('pre_delivery=0','pre_delivery=1'),
            ('snapshots=1','snapshots=0'),('mutations=11','mutations=12'),('bindings=2','bindings=0'),
            ('unbound_denied=1','unbound_denied=0'),('mapped=4','mapped=3'),('backend=41','backend=18446744073709551615')]:
            with self.subTest(before=before),self.assertRaises(ValueError):v.file_report(good.replace(before,after))
        b=bytearray.fromhex(f['report'])
        for offset in range(256):
            bad=bytearray(b);bad[offset]^=0x80
            with self.subTest(offset=offset),self.assertRaises(ValueError):v.file_report(good.replace(f['report'],bad.hex()))

    def test_strict_serial_cannot_hide_duplicate_noncanonical_or_wrapped_fields(self):
        good=file_line()
        for bad in [good+good,good.replace('calls=52','calls=052'),good.replace(' report=',' extra=0 report='),
                    good.replace('EVROSION_M3_FILE','EVROSION_M3_FILE\t')]:
            with self.assertRaises(ValueError):v.file_report(bad)
        for bad in ['-1','00','+1','1.0',str(1<<64),' 1']:
            with self.assertRaises(ValueError):v.uint(bad)

    def test_live_progress_cannot_reset_deadline_reverse_stop_or_overflow(self):
        good=dict(start_tick=100,observed_tick=164,stop_tick=165)
        self.assertEqual(v.progress_record(good),good)
        for changes in [dict(observed_tick=163),dict(stop_tick=163),dict(start_tick=(1<<64)-64),
                        dict(start_tick=True),dict(observed_tick=-1),dict(unclaimed=0)]:
            with self.assertRaises(ValueError):v.progress_record({**good,**changes})

    def test_logical_file_envelope_never_confuses_counter_with_global_operation(self):
        b=bytearray(33);b[:8]=b'EVFILE01';b[8:10]=b'\x01\0';b[10:12]=(1).to_bytes(2,'little');b[32]=42
        self.assertEqual(v.file_envelope(b),(0,0,b'*'))
        b[16:24]=(1).to_bytes(8,'little');b[24:32]=(17).to_bytes(8,'little')
        self.assertEqual(v.file_envelope(b),(1,17,b'*'))
        for offset in [0,8,10,12,13,14,15]:
            changed=bytearray(b);changed[offset]^=1
            with self.assertRaises(ValueError):v.file_envelope(changed)
        for offset in [16,24]:
            changed=bytearray(b);changed[offset:offset+8]=((1<<64)-1).to_bytes(8,'little')
            with self.assertRaises(ValueError):v.file_envelope(changed)
        with self.assertRaises(ValueError):v.file_envelope(b+b'\0')

    def test_owner_choice_requires_whole_line_not_r_substring_or_unterminated_input(self):
        for bad in [b'r',b'q',b'noise r\n',b'rx\n',b'\x1br\n',b' rr\n']:
            self.assertIsNone(v.chosen_line(bad))
        self.assertEqual(v.chosen_line(b'noise r\nq\n'),2)
        self.assertEqual(v.chosen_line(b' \tR\r\n'),1)
        self.assertEqual(v.chosen_line(b'q\nr\n'),2)

    def test_actual_owner_budget_refuses_unbalanced_or_unbounded_claims(self):
        good=dict(elapsed=1000,driver=700,controller=200,critical=100,parent=1000,transitions=40000)
        v.owner_budget(good)
        for changes in [dict(elapsed=65536),dict(parent=999),dict(driver=701),dict(controller=True),
                        dict(transitions=0),dict(transitions=8000001),dict(critical=-1)]:
            with self.assertRaises(ValueError):v.owner_budget({**good,**changes})

    def test_resume_cannot_start_from_a_boolean_or_manufactured_origin(self):
        for origin in [{},{'passed':True},{'schema':1,'kind':'prepared-owner-import','read_only':False},
                       {'schema':1,'kind':'prepared-owner-import','read_only':True,'publisher_authenticated':True}]:
            with self.assertRaises(ValueError):v.prepared_origin(origin,{})

    def test_eof_cannot_invent_completion_borrow_latest_state_or_hide_any_mutation(self):
        prepared=bytes(v.DISK_BYTES)
        before=bytearray(prepared);before[1024:1028]=b'EVGT';before=bytes(before)
        good=dict(guest_completed=False,eof_no_action=True,guest_report=None)
        v.no_guest_completion(good,before,before,prepared)
        for bad in [dict(good,guest_completed=True),dict(good,eof_no_action=False),
                    dict(good,guest_report={'passed':True}),dict(good,actual={'mode':'owner-recover'})]:
            with self.assertRaises(ValueError):v.no_guest_completion(bad,before,before,prepared)
        with self.assertRaises(ValueError):v.no_guest_completion(good,before,before,None)
        changed=bytearray(before);changed[16*512]^=1
        with self.assertRaises(ValueError):v.no_guest_completion(good,before,changed,prepared)
        # Even unchanged EOF bytes cannot borrow a DIFFERENT earlier baseline.
        with self.assertRaises(ValueError):v.no_guest_completion(good,changed,changed,prepared)

    def test_import_requires_unique_real_failure_before_unique_preparation(self):
        failure={'path':'fail-b/phase-result.json'};prepared={'path':'owner-prepare3/phase-result.json'}
        self.assertEqual([row[0] for row in v.prepared_phase_order([failure,prepared])],[0,1])
        for bad in [[],[prepared],[failure],[prepared,failure],[failure,prepared,prepared],[failure,failure,prepared]]:
            with self.assertRaises(ValueError):v.prepared_phase_order(bad)

    def test_latest_generation_family_excludes_progress_without_skipping_failures(self):
        with tempfile.TemporaryDirectory(dir=v.ROOT/'build/test-tmp') as root:
            root=Path(root)
            for name in ['generation-1','generation-progress-2']:
                path=root/'build/m3/evidence'/name
                path.mkdir(parents=True);(path/'results.json').write_text('{}')
            with patch.object(v,'ROOT',root):
                self.assertEqual(v.latest('generation').name,'generation-1')

    def test_fresh_selects_one_top_level_suite_amid_nested_and_unrelated_announcements(self):
        with tempfile.TemporaryDirectory(dir=v.ROOT/'build/test-tmp') as root:
            root=Path(root)
            top=root/'build/m3/evidence/storage-pio-123-456'
            top.mkdir(parents=True)
            text='\n'.join(f'Evidence: {p}' for p in [top,top/'write/boot',top/'verify/boot',
                         root/'build/m0/evidence/boot-123-456',top])+'\n'
            with patch.object(v,'ROOT',root):
                self.assertEqual(v.fresh_evidence('pio',text),top)
                self.assertEqual(v.fresh_evidence('pio',text.replace('\n','\r\n')),top)
                self.assertEqual(v.fresh_evidence('pio','Evidence: build/m3/evidence/storage-pio-123-456\n'),top)
                for bad in [f'Evidence: {top}/write/boot\n',
                            f'Evidence: {root}/unrelated/storage-pio-123-456\n',
                            f'Evidence: {top}\nEvidence: {top.parent}/storage-pio-123-789\n',
                            f'Evidence: {top.parent}/storage-pio-123\n',
                            f'Evidence: {top.parent}/generation-progress-123-456\n',
                            f'Evidence: {top}/results.json\n']:
                    with self.subTest(text=bad),self.assertRaises(ValueError):v.fresh_evidence('pio',bad)


if __name__=='__main__':unittest.main()
