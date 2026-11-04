-- Admit only the two implemented delivery protocols into the independent
-- program catalog. Preserve every node, facts, size, visit and outcome check.
-- Migration37 is already applied by native fixtures and remains unchanged.
CREATE OR REPLACE FUNCTION freightctl_program_compile(d jsonb,facts jsonb) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE catalog jsonb:='{}';item jsonb;key text;stat jsonb;result jsonb;f jsonb;s jsonb;
BEGIN
 IF d->'schema_version' IS DISTINCT FROM '2'::jsonb OR jsonb_typeof(d->'program') IS DISTINCT FROM 'object' OR (d->'program')-'nodes'<>'{}'::jsonb OR jsonb_typeof(d->'program'->'nodes') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'program'->'nodes')<1 OR jsonb_typeof(d->'steps') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'steps')>16 OR jsonb_typeof(facts) IS DISTINCT FROM 'object' OR facts-ARRAY['file','source']<>'{}'::jsonb THEN RETURN NULL;END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(d->'steps') LOOP
  key:=item->>'id';IF coalesce(item->>'kind','') NOT IN ('sftp.deliver','ftps.deliver') OR key IS NULL OR key !~ '^[a-z][a-z0-9_]{0,63}$' OR catalog ? key THEN RETURN NULL;END IF;catalog:=catalog||jsonb_build_object(key,true);
 END LOOP;
 f:=facts->'file';IF EXISTS(SELECT 1 FROM unnest(ARRAY['id','accepted_event_id','sha256','policy']) k WHERE jsonb_typeof(f->k) IS DISTINCT FROM 'string') THEN RETURN NULL;END IF;IF jsonb_typeof(f) IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(f) ORDER BY 1) IS DISTINCT FROM ARRAY['accepted_event_id','id','policy','sha256','size_bytes']::text[] OR jsonb_typeof(f->'size_bytes') IS DISTINCT FROM 'number' OR f->>'size_bytes' !~ '^(0|[1-9][0-9]*)$' OR (f->>'size_bytes')::numeric>1073741824 OR f->>'id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR f->>'accepted_event_id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR f->>'sha256' !~ '^[0-9a-f]{64}$' OR freightctl_program_text(f->'policy') IS NOT TRUE THEN RETURN NULL;END IF;
 IF d ? 'source' THEN
  s:=facts->'source';IF EXISTS(SELECT 1 FROM unnest(ARRAY['collection_id','manifest_hash','name','batch_id']) k WHERE jsonb_typeof(s->k) IS DISTINCT FROM 'string') THEN RETURN NULL;END IF;IF jsonb_typeof(s) IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(s) ORDER BY 1) IS DISTINCT FROM ARRAY['batch_id','collection_id','file_count','index','manifest_hash','name']::text[] OR s->>'collection_id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR s->>'batch_id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR s->>'manifest_hash' !~ '^[0-9a-f]{64}$' OR s->>'name' !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' OR right(s->>'name',11)='.ready.json' OR jsonb_typeof(s->'file_count') IS DISTINCT FROM 'number' OR jsonb_typeof(s->'index') IS DISTINCT FROM 'number' OR s->>'file_count' !~ '^[1-9][0-9]*$' OR s->>'index' !~ '^(0|[1-9][0-9]*)$' OR (s->>'file_count')::integer>(d->'source'->>'max_files')::integer OR (s->>'index')::integer>=(s->>'file_count')::integer OR (f->>'size_bytes')::bigint>(d->'source'->>'max_file_bytes')::bigint THEN RETURN NULL;END IF;
 ELSIF facts ? 'source' THEN RETURN NULL;END IF;
 stat:=freightctl_program_nodes_cost(d->'program'->'nodes',catalog,d ? 'source','{}');IF stat IS NULL THEN RETURN NULL;END IF;
 result:=freightctl_program_nodes(d->'program'->'nodes',facts,'{}');IF result IS NULL OR (jsonb_array_length(result->'selected_steps')=0 AND NOT(result ? 'local_reason')) THEN RETURN NULL;END IF;
 result:=jsonb_build_object('schema_version',1,'facts',facts)||result;IF octet_length(result::text)>32768 THEN RETURN NULL;END IF;RETURN result;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;
