import importlib.util
import json
from pathlib import Path
import unittest
SPEC=importlib.util.spec_from_file_location('generate_file',Path(__file__).with_name('generate_file.py'))
GEN=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(GEN)

class GeneratorTests(unittest.TestCase):
    def test_exact_schema_reproduces_actual_output(self):
        self.assertEqual(GEN.render(GEN.SOURCE.read_bytes(),GEN.TEMPLATE.read_text()),GEN.OUTPUT.read_text())
    def test_unknown_methods_selectors_bounds_and_semantics_refuse_generation(self):
        original=json.loads(GEN.SOURCE.read_bytes())
        mutations=[lambda value:value['wire']['methods'].update({'format_volume':3}),
                   lambda value:value['wire'].update({'object_id':'u64'}),
                   lambda value:value['wire'].update({'payload_bytes':225}),
                   lambda value:value['durable_retry'].update({'retention':'unlimited_exactly_once'}),
                   lambda value:value['transport'].update({'automatic_retry':True})]
        for mutation in mutations:
            value=json.loads(json.dumps(original));mutation(value)
            with self.assertRaises(ValueError):GEN.render(json.dumps(value).encode(),GEN.TEMPLATE.read_text())
    def test_duplicate_fields_and_stale_generated_output_are_detectable(self):
        source=GEN.SOURCE.read_bytes().replace(b'"schema": 1',b'"schema": 1,"schema": 1')
        with self.assertRaises(ValueError):GEN.render(source,GEN.TEMPLATE.read_text())
        self.assertNotEqual(GEN.render(GEN.SOURCE.read_bytes(),GEN.TEMPLATE.read_text()),GEN.OUTPUT.read_text()+'stale')
if __name__=='__main__':unittest.main()
