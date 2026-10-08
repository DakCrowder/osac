import {
  Card,
  CardBody,
  CardHeader,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Flex,
  FlexItem,
  Icon,
  MenuToggle,
} from '@patternfly/react-core';
import { EllipsisVIcon } from '@patternfly/react-icons/dist/esm/icons/ellipsis-v-icon';
import KeyIcon from '@patternfly/react-icons/dist/esm/icons/key-icon';
import { ActionsColumn } from '@patternfly/react-table';

import { Secret, SecretType } from '@osac/types';
import { useTranslation } from '@osac/ui-components/hooks/useTranslation';

import { getSecretType, getSecretTypeDataKeys } from './utils.ts';
import { Timestamp } from '../Primitives/Timestamp';
import ResourceNameField from '../Resource/ResourceNameField';

interface SecretCardProps {
  secret: Secret;
  onEdit: () => void;
  onDelete: () => void;
}

const SecretCard = ({ secret, onEdit, onDelete }: SecretCardProps) => {
  const { t } = useTranslation();
  const secretTypes = getSecretType(t);
  const typeLabel = secretTypes[secret.type] || secretTypes[SecretType.UNSPECIFIED];
  const dataKeys = getSecretTypeDataKeys(secret.type);

  return (
    <Card isFullHeight>
      <CardHeader
        actions={{
          actions: (
            <ActionsColumn
              items={[
                { title: t('Edit'), onClick: onEdit },
                { title: t('Delete'), onClick: onDelete },
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
          ),
        }}
      >
        <Flex spaceItems={{ default: 'spaceItemsSm' }} alignItems={{ default: 'alignItemsCenter' }}>
          <FlexItem>
            <Icon size="lg">
              <KeyIcon />
            </Icon>
          </FlexItem>
          <FlexItem>
            <ResourceNameField resource={secret} detailsUrl={`/secrets/${secret.id}`} />
          </FlexItem>
        </Flex>
      </CardHeader>
      <CardBody>
        <DescriptionList isCompact isHorizontal>
          <DescriptionListGroup>
            <DescriptionListTerm>{t('Type')}</DescriptionListTerm>
            <DescriptionListDescription>{typeLabel}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{t('Keys')}</DescriptionListTerm>
            <DescriptionListDescription>{dataKeys || '-'}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>{t('Added')}</DescriptionListTerm>
            <DescriptionListDescription>
              <Timestamp value={secret.metadata?.creationTimestamp} />
            </DescriptionListDescription>
          </DescriptionListGroup>
        </DescriptionList>
      </CardBody>
    </Card>
  );
};

export default SecretCard;
