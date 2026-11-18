"""Closed owned-VM diagnostic; wire bytes never grant process control."""
import json
EXPECTED={'schema':1,'interface':'ev.test.document','version':1,'maturity':'Internal','scope':'explicit_owned_VM_development_diagnostic_only','wire':{'bytes':8,'magic':'DX','version_byte':1,'commands':{'CrashApplication':1},'reserved_zero':[4,5,6,7]},'transport':{'capabilities':0,'sender':'actual_current_Root_on_retained_App_control_route','authority':'none_packet_cannot_nominate_a_target_or_grant_control','effect':'explicit_owner_request_for_real_current_App_user_fault_no_host_register_or_pixel_substitution'}}
def schema(source):
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate document test field: '+key)
            value[key]=item
        return value
    value=json.loads(source,object_pairs_hook=unique)
    canonical=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'))
    if canonical(value)!=canonical(EXPECTED):raise ValueError('unsupported ev.test.document@1 profile')
    return value
