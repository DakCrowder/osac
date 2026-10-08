import { MenuToggle } from '@patternfly/react-core';
import { EllipsisVIcon } from '@patternfly/react-icons/dist/esm/icons/ellipsis-v-icon';
import { ActionsColumn, Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';

import { Secret, SecretType } from '@osac/types';
import { useTranslation } from '@osac/ui-components/hooks/useTranslation';

import { getSecretType } from './utils.ts';
import { Timestamp } from '../Primitives/Timestamp';
import ResourceNameField from '../Resource/ResourceNameField';

interface SecretTableProps {
  items: Secret[];
  onEdit: (secret: Secret) => void;
  onDelete: (secret: Secret) => void;
}

const SecretTable = ({ items, onEdit, onDelete }: SecretTableProps) => {
  const { t } = useTranslation();
  const secretTypes = getSecretType(t);
  const nameLabel = t('Name');
  const projectLabel = t('Project');
  const typeLabel = t('Type');
  const createdLabel = t('Created');
  const actionsLabel = t('Actions');

  return (
    <Table aria-label={t('Secrets')} variant="compact">
      <Thead>
        <Tr>
          <Th>{nameLabel}</Th>
          <Th>{projectLabel}</Th>
          <Th>{typeLabel}</Th>
          <Th>{createdLabel}</Th>
          <Th aria-label={actionsLabel} />
        </Tr>
      </Thead>
      <Tbody>
        {items.map((secret) => (
          <Tr key={secret.id}>
            <Td dataLabel={nameLabel}>
              <ResourceNameField resource={secret} detailsUrl={`/secrets/${secret.id}`} />
            </Td>
            <Td dataLabel={projectLabel}>{secret.metadata?.project || t('Default')}</Td>
            <Td dataLabel={typeLabel}>
              {secretTypes[secret.type] || secretTypes[SecretType.UNSPECIFIED]}
            </Td>
            <Td dataLabel={createdLabel}>
              <Timestamp value={secret.metadata?.creationTimestamp} />
            </Td>
            <Td dataLabel={actionsLabel} isActionCell>
              <ActionsColumn
                items={[
                  { title: t('Edit'), onClick: () => onEdit(secret) },
                  { title: t('Delete'), onClick: () => onDelete(secret) },
                ]}
                actionsToggle={({ onToggle, isOpen, toggleRef }) => (
                  <MenuToggle
                    ref={toggleRef}
                    variant="plain"
                    isExpanded={isOpen}
                    onClick={onToggle}
                    aria-label={t('Actions for {{name}}', { name: secret.metadata?.name })}
                  >
                    <EllipsisVIcon />
                  </MenuToggle>
                )}
              />
            </Td>
          </Tr>
        ))}
      </Tbody>
    </Table>
  );
};

export default SecretTable;
