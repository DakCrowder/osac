--
-- Copyright (c) 2026 Red Hat Inc.
--
-- Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
-- the License. You may obtain a copy of the License at
--
--   http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
-- an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
-- specific language governing permissions and limitations under the License.
--

-- Prevent soft-deleting Secrets while an active resource references it. HUB-backed Secrets are exempt so
-- the Cluster reconciler can remove system owned Secrets before deleting the Cluster that references them.
create index clusters_pull_secret_secret on clusters
  ((data->'spec'->'pull_secret_secret'->>'id'))
  where data->'spec'->'pull_secret_secret'->>'id' is not null;

create index cluster_templates_pull_secret_secret on cluster_templates
  ((data->'spec_defaults'->'pull_secret_secret'->>'id'))
  where data->'spec_defaults'->'pull_secret_secret'->>'id' is not null;

create index hubs_kubeconfig_secret on hubs
  ((data->'spec'->'kubeconfig_secret'->>'id'))
  where data->'spec'->'kubeconfig_secret'->>'id' is not null;

create index identity_providers_client_secret_secret on identity_providers
  ((data->'spec'->'open_id_connect'->'client_secret_secret'->>'id'))
  where data->'spec'->'open_id_connect'->'client_secret_secret'->>'id' is not null;

create index storage_backends_password_secret on storage_backends
  ((data->'spec'->'credentials'->'password_secret'->>'id'))
  where data->'spec'->'credentials'->'password_secret'->>'id' is not null;

-- Validate Secret references while taking a row lock that conflicts with a concurrent
-- Secret soft-delete. Without this reciprocal lock, a delete can observe no committed
-- dependents while a concurrent dependent creation is still uncommitted.
create function check_secret_ref_exists() returns trigger as $$
declare
  secret_id text;
  old_secret_id text;
  found_id text;
begin
  secret_id := case tg_table_name
    when 'clusters' then new.data->'spec'->'pull_secret_secret'->>'id'
    when 'cluster_templates' then new.data->'spec_defaults'->'pull_secret_secret'->>'id'
    when 'hubs' then new.data->'spec'->'kubeconfig_secret'->>'id'
    when 'identity_providers' then new.data->'spec'->'open_id_connect'->'client_secret_secret'->>'id'
    when 'storage_backends' then new.data->'spec'->'credentials'->'password_secret'->>'id'
  end;

  if tg_op = 'UPDATE' and old.deletion_timestamp = 'epoch' then
    old_secret_id := case tg_table_name
      when 'clusters' then old.data->'spec'->'pull_secret_secret'->>'id'
      when 'cluster_templates' then old.data->'spec_defaults'->'pull_secret_secret'->>'id'
      when 'hubs' then old.data->'spec'->'kubeconfig_secret'->>'id'
      when 'identity_providers' then old.data->'spec'->'open_id_connect'->'client_secret_secret'->>'id'
      when 'storage_backends' then old.data->'spec'->'credentials'->'password_secret'->>'id'
    end;

    if secret_id is not distinct from old_secret_id then
      return new;
    end if;
  end if;

  if coalesce(secret_id, '') = '' then
    return new;
  end if;

  select id into found_id
  from secrets
  where id = secret_id
    and deletion_timestamp = 'epoch'
  for share;

  if found_id is null then
    raise exception using
      errcode = 'Z0002',
      message = format('Secret ''%s'' does not exist or has been deleted', secret_id);
  end if;

  return new;
end;
$$ language plpgsql;

create trigger check_secret_ref_exists
  before insert or update of data, deletion_timestamp on clusters
  for each row
  when (new.deletion_timestamp = 'epoch')
  execute function check_secret_ref_exists();

create trigger check_secret_ref_exists
  before insert or update of data, deletion_timestamp on cluster_templates
  for each row
  when (new.deletion_timestamp = 'epoch')
  execute function check_secret_ref_exists();

create trigger check_secret_ref_exists
  before insert or update of data, deletion_timestamp on hubs
  for each row
  when (new.deletion_timestamp = 'epoch')
  execute function check_secret_ref_exists();

create trigger check_secret_ref_exists
  before insert or update of data, deletion_timestamp on identity_providers
  for each row
  when (new.deletion_timestamp = 'epoch')
  execute function check_secret_ref_exists();

create trigger check_secret_ref_exists
  before insert or update of data, deletion_timestamp on storage_backends
  for each row
  when (new.deletion_timestamp = 'epoch')
  execute function check_secret_ref_exists();

create function check_secret_not_in_use() returns trigger as $$
begin
  if old.data->>'backend' = 'SECRET_BACKEND_HUB' then
    return new;
  end if;

  if exists (
    select 1
    from active_clusters a
    join clusters c on c.id = a.id
    where c.data->'spec'->'pull_secret_secret'->>'id' = old.id
  ) or exists (
    select 1
    from active_cluster_templates a
    join cluster_templates c on c.id = a.id
    where c.data->'spec_defaults'->'pull_secret_secret'->>'id' = old.id
  ) or exists (
    select 1
    from active_hubs a
    join hubs h on h.id = a.id
    where h.data->'spec'->'kubeconfig_secret'->>'id' = old.id
  ) or exists (
    select 1
    from active_identity_providers a
    join identity_providers i on i.id = a.id
    where i.data->'spec'->'open_id_connect'->'client_secret_secret'->>'id' = old.id
  ) or exists (
    select 1
    from active_storage_backends a
    join storage_backends s on s.id = a.id
    where s.data->'spec'->'credentials'->'password_secret'->>'id' = old.id
  ) then
    raise exception using
      errcode = 'Z0003',
      message = format('cannot delete Secret ''%s'': it is in use by at least one active resource', old.id);
  end if;

  return new;
end;
$$ language plpgsql;

create trigger check_secret_not_in_use
  before update on secrets
  for each row
  when (old.deletion_timestamp = 'epoch' and new.deletion_timestamp != 'epoch')
  execute function check_secret_not_in_use();
