"""Replay frozen responses against the staged implementation; no HTTP."""
import json, sys
from pathlib import Path
from collections import Counter
WORK=Path(__file__).resolve().parents[1]
OUT=WORK/'artifacts/detection-quality'
sys.path.insert(0,str(WORK/'src'))
from ultimate_username.detection import DetectionEngine
from ultimate_username.domain.models import SiteDefinition, TransportResponse
from ultimate_username.domain.codec import from_value,to_value
from ultimate_username.planning import plan_request
from ultimate_username.enrichment import enrich
from ultimate_username.field_model import field_spec,FieldGroup
def main():
    cases=json.loads((OUT/'candidate-audit.json').read_text('utf-8')); rows=[]; images=[]
    for c in cases:
        site=from_value(SiteDefinition,c['site']); old=c['result']; last=old['attempts'][-1]
        response=TransportResponse(last['url'],c['status'],(OUT/c['body_file']).read_bytes(),headers=tuple(tuple(x) for x in c['response']['headers']),final_url=old['final_url'],body_complete=c['response']['body_complete'])
        result=DetectionEngine().detect(response,plan_request('Sampler51',site,'replay'))
        metadata=enrich(response,'Sampler51',site,result)
        fields={f.name:to_value(f.value) for f in metadata.fields+metadata.extra_fields if f.name not in metadata.conflicts and field_spec(f.name).group!=FieldGroup.TECHNICAL}
        row={'site':site.name,'site_id':site.id,'profile_url':old['profile_url'],'before':old['detection'],'after':to_value(result),'metadata':to_value(metadata),'useful_fields':fields,'verified':c['audit']['verified_profile'],'audit_classification':c['audit']['classification']}
        rows.append(row)
        if row['verified'] and result.verdict=='FOUND':
            media=[f for f in metadata.fields+metadata.extra_fields if f.name in ('avatar_url','banner_url') and f.name in fields]
            if media:images.append({'site':site.name,'username':fields.get('username','Sampler51'),'profile_url':old['profile_url'],'avatar_url':fields.get('avatar_url'),'banner_url':fields.get('banner_url'),'other_profile_image_urls':[], 'provenance':to_value(media),'verification_strength':result.confidence.strength,'association_note':'URL from owner-bound object; no claim of a custom or unique identity image. GOG background is predefined.'})
    positives=[r for r in rows if r['after']['verdict'] in ('FOUND','PROBABLE')]; truth=[r for r in rows if r['verified']]
    summary={'baseline_found':1,'baseline_probable':22,'verified_profiles':len(truth),'baseline_false_positive_candidates':len(rows)-len(truth),'after_verdicts':dict(Counter(r['after']['verdict'] for r in rows)),'after_response_classes':dict(Counter(r['after']['response_class'] for r in rows)),
        'candidate_precision_before':len(truth)/len(rows),'candidate_precision_after':sum(r['verified'] for r in positives)/len(positives),
        'candidate_false_positive_rate_after':sum(not r['verified'] for r in positives)/(len(rows)-len(truth)),
        'known_verified_profiles_retained':sum(r['verified'] for r in positives),'profiles_with_metadata':sum(bool(r['useful_fields']) for r in rows if r['verified']),
        'useful_fields':sum(len(r['useful_fields']) for r in rows if r['verified']),'profiles_with_avatar':sum(bool(r['useful_fields'].get('avatar_url')) for r in rows if r['verified']),
        'measurement_scope':'23 manually classified baseline candidates used for development, not independent holdout. No global recall/FPR estimate.'}
    (OUT/'replay.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
    (OUT/'replay-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    (WORK/'VERIFIED_PROFILE_IMAGES.json').write_text(json.dumps(images,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# Verified profiles from frozen Ultimate responses','','Verification binds a nickname to a response; it does not connect accounts to the same person.','']
    for r in rows:
        if r['verified']:lines += ['## '+r['site'],'',r['profile_url'],'','```json',json.dumps(r['useful_fields'],ensure_ascii=False,indent=2),'```','']
    (WORK/'VERIFIED_MATCHES.md').write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps(summary))
if __name__=='__main__': main()
