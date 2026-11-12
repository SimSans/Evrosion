"""Closed async private-data generation: legacy integrity and atomic rejection."""
import contextlib,copy,hashlib,io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import generate
class AppDataTests(unittest.TestCase):
 def setUp(self):self.source=generate.APP_DATA_SOURCE.read_bytes();self.value=json.loads(self.source)
 def test_exact_generated_data_and_all_earlier_outputs_stay_independent(self):
  self.assertEqual(generate.APP_DATA_OUTPUT.read_text(),generate.render_app_data(self.source))
  for source,output,render in [(generate.SOURCE,generate.OUTPUT,generate.render),(generate.CAP_SOURCE,generate.CAP_OUTPUT,generate.render_cap),(generate.PROVIDER_SOURCE,generate.PROVIDER_OUTPUT,generate.render_provider)]:self.assertEqual(output.read_text(),render(source.read_bytes()))
  with self.assertRaises(ValueError):generate.render_provider(self.source)
 def test_authority_and_transport_semantics_cannot_be_silently_reinterpreted(self):
  for path,replacement in [(('version',),True),(('maturity',),'Stable'),(('wire','bytes'),16),(('wire','magic'),'EV'),(('wire','requests','Read','value'),1),(('wire','requests','SetValue','value'),'u64'),(('wire','replies','Refused','reasons','Storage'),5),(('transport','mode'),'non_reentrant_sync'),(('transport','max_capabilities'),1),(('transport','max_outstanding_per_actual_incarnation'),2),(('transport','retry'),'automatic'),(('transport','authority'),'AppId_from_wire')]:
   value=copy.deepcopy(self.value);field=value
   for name in path[:-1]:field=field[name]
   field[path[-1]]=replacement
   with self.subTest(path=path),self.assertRaises(ValueError):generate.render_app_data(json.dumps(value).encode())
 def test_missing_unknown_duplicate_and_trailing_data_refuse_before_any_output_write(self):
  for source in [b'{}',b'[]',b'null',self.source+b'{}',self.source.replace(b'"schema": 1,',b'"schema": 1, "schema": 1,')]:
   with self.assertRaises(ValueError):generate.render_app_data(source)
  value=copy.deepcopy(self.value);value['wire']['AppId']='u64'
  with self.assertRaises(ValueError):generate.render_app_data(json.dumps(value).encode())
  scratch=generate.ROOT/'build/test-tmp';scratch.mkdir(parents=True,exist_ok=True)
  with tempfile.TemporaryDirectory(dir=scratch)as directory:
   directory=Path(directory);bad=directory/'bad.json';bad.write_text('{}');names=['OUTPUT','CAP_OUTPUT','PROVIDER_OUTPUT','APP_DATA_OUTPUT'];outputs=[]
   for name in names:
    path=directory/(name+'.rs');path.write_text('preserve-'+name);outputs.append(path)
   before=[p.read_bytes()for p in outputs]
   with contextlib.ExitStack()as stack:
    stack.enter_context(patch.object(generate,'APP_DATA_SOURCE',bad));stack.enter_context(patch('sys.argv',['generate.py']));stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
    for name,path in zip(names,outputs):stack.enter_context(patch.object(generate,name,path))
    self.assertEqual(generate.main(),1)
   self.assertEqual([p.read_bytes()for p in outputs],before)
if __name__=='__main__':unittest.main()
