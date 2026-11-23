--
-- Copyright (c) 2026 Red Hat Inc.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--   http://www.apache.org/licenses/LICENSE-2.0
--

-- Ordinary users and IdP managers retain project-manager operations, which
-- also require the manager group for the target project at request time.
update roles as r
set data = jsonb_set(r.data, '{spec,permissions}', (
  select jsonb_agg(
    case rule->>'service'
      when 'osac.public.projects' then rule || '{"methods":["get","list","update","delete"]}'::jsonb
      when 'osac.public.projectmemberships' then rule || '{"methods":["create","get","list","update","delete"]}'::jsonb
      else rule
    end
    order by position
  )
  from jsonb_array_elements(r.data #> '{spec,permissions}') with ordinality as permissions(rule, position)
))
where r.id in (
  '019dd9f6-36cf-77bc-8041-c6a6a415c185', -- tenant-user
  '019dd9f6-d573-beaa-41c5-96965e594cc6'  -- tenant-idp-manager
);

-- The legacy reader personas share the same reviewed method set. Preserve
-- that set instead of extending provider readers to every public API.
update roles as provider
set data = jsonb_set(provider.data, '{spec,permissions}', tenant.data #> '{spec,permissions}')
from roles tenant
where provider.id = '019dd9f6-36cc-7a35-bfc5-242833f11c2f'
  and tenant.id = '019dd9f6-36ce-78fc-96d8-b87cf58bf14c';
