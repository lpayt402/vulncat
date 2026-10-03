import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Group,
  Modal,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea,
  Title,
} from '@mantine/core';
import { apiRequest } from '../api/client';
import { formatDate, humanize } from '../utils/format';

type ReviewStatus = 'open' | 'deferred' | 'assigned' | 'rejected';
type DecisionAction = 'assign' | 'create' | 'reject' | 'defer' | 'merge' | 'split' | 'undo';

interface PersistentItem {
  id: string;
  asset_id: string | null;
  asset_name?: string | null;
  version: number;
  review_status: ReviewStatus;
  rule?: string;
  explanation?: string;
  confidence?: number;
  candidate_ids: string[];
  observation: {
    kind?: string;
    asset?: {
      fqdn?: string;
      short_hostname?: string;
      ip_addresses?: string[];
      native_ids?: Array<{ source?: string; instance?: string; kind?: string; value?: string }>;
    };
    observed_at?: string | null;
    warnings?: string[];
    vulnerability?: { vulnerability_id?: string | null; native_status?: string | null; cves?: string[] };
    coverage?: { outcome?: string | null; complete?: boolean | null; authenticated?: boolean | null };
    provenance?: {
      source?: string;
      instance?: string;
      record_number?: number;
      filename?: string;
      file_sha256?: string;
    };
    [key: string]: unknown;
  };
}

interface ObservationPage {
  revision: number;
  total: number;
  offset: number;
  limit: number;
  items: PersistentItem[];
}

interface AssetChoice {
  id: string;
  canonical_hostname: string | null;
  display_name?: string;
}

interface DecisionItem {
  id: string;
  action: DecisionAction;
  reason: string;
  actor_user_id?: string | null;
  occurred_at: string;
  undo_of_id?: string | null;
  undone: boolean;
  reversible: boolean;
}

interface DecisionPage {
  revision: number;
  total: number;
  items: DecisionItem[];
}

interface ObservationDetail extends PersistentItem {
  locators: Array<{
    batch_id: string;
    file_sha256: string;
    filename: string;
    record_number: number;
    imported_at: string;
  }>;
  locator_total: number;
  history: Array<{
    version: number;
    asset_id: string | null;
    review_status: ReviewStatus;
    decision_id: string | null;
    occurred_at: string;
  }>;
  history_total: number;
}

interface DecisionPayload {
  request_key: string;
  expected_revision: number;
  reason: string;
  action: DecisionAction;
  observation_ids: string[];
  expected_versions: Record<string, number>;
  source_asset_id?: string;
  target_asset_id?: string;
  undo_decision_id?: string;
}

interface PendingDecision {
  payload: DecisionPayload;
  consequence: string;
}

const reviewOptions = [
  { value: 'open', label: 'Open review' },
  { value: 'deferred', label: 'Deferred' },
  { value: 'assigned', label: 'Assigned' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'all', label: 'All evidence' },
];

const actionOptions = [
  { value: 'assign', label: 'Assign to an asset' },
  { value: 'create', label: 'Create a separate asset' },
  { value: 'reject', label: 'Reject this evidence' },
  { value: 'defer', label: 'Defer for later review' },
  { value: 'merge', label: 'Merge assets' },
  { value: 'split', label: 'Split selected evidence' },
  { value: 'undo', label: 'Undo a decision' },
];
const assetPageSize = 20;

function requestKey() {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function identity(item: PersistentItem) {
  const asset = item.observation.asset;
  const identifiers = [
    asset?.fqdn,
    asset?.short_hostname,
    ...(asset?.ip_addresses ?? []),
    ...(asset?.native_ids ?? []).map((entry) => [entry.source, entry.instance, entry.kind, entry.value].filter(Boolean).join(' · ')),
  ].filter(Boolean);
  return [...new Set(identifiers)].join(' · ') || `Evidence ${item.id.slice(0, 8)}`;
}

function newErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'The request failed. Try again.';
}

function statusConflict(error: unknown) {
  const status = error && typeof error === 'object' && 'status' in error ? Number(error.status) : 0;
  return status === 409 || (error instanceof Error && /^409\b/.test(error.message));
}

function assetDisplayName(asset: AssetChoice | undefined) {
  return asset?.display_name?.trim() || asset?.canonical_hostname?.trim() || 'Unnamed asset';
}

function assetChoiceLabel(asset: AssetChoice) {
  return `${assetDisplayName(asset)} (ID: ${asset.id})`;
}

function yesNoUnknown(value: boolean | null | undefined) {
  return value == null ? 'Not provided' : value ? 'Yes' : 'No';
}

export function PersistentReconciliation({ refreshToken = 0 }: { refreshToken?: number }) {
  const [reviewStatus, setReviewStatus] = useState('open');
  const [sourceFilter, setSourceFilter] = useState('');
  const [appliedSource, setAppliedSource] = useState('');
  const [offset, setOffset] = useState(0);
  const [decisionOffset, setDecisionOffset] = useState(0);
  const [observationPage, setObservationPage] = useState<ObservationPage | null>(null);
  const [decisionPage, setDecisionPage] = useState<DecisionPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [detail, setDetail] = useState<ObservationDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [assetSearch, setAssetSearch] = useState('');
  const [assets, setAssets] = useState<AssetChoice[]>([]);
  const [assetOffset, setAssetOffset] = useState(0);
  const [assetTotal, setAssetTotal] = useState(0);
  const [assetsError, setAssetsError] = useState<string | null>(null);
  const [assetSearchLoading, setAssetSearchLoading] = useState(false);
  const [action, setAction] = useState<DecisionAction>('assign');
  const [reason, setReason] = useState('');
  const [targetAssetId, setTargetAssetId] = useState<string | null>(null);
  const [sourceAssetId, setSourceAssetId] = useState<string | null>(null);
  const [undoDecision, setUndoDecision] = useState<DecisionItem | null>(null);
  const [pendingDecision, setPendingDecision] = useState<PendingDecision | null>(null);
  const [savingDecision, setSavingDecision] = useState(false);
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const [decisionConflict, setDecisionConflict] = useState(false);
  const loadVersion = useRef(0);
  const detailRequestVersion = useRef(0);

  const refreshEvidence = useCallback(async () => {
    const version = ++loadVersion.current;
    detailRequestVersion.current += 1;
    setDetail(null);
    setDetailError(null);
    setLoading(true);
    setLoadError(null);
    const query = new URLSearchParams({ offset: String(offset), limit: '50' });
    if (reviewStatus !== 'all') query.set('review_status', reviewStatus);
    if (appliedSource.trim()) query.set('source', appliedSource.trim());
    try {
      const [observations, decisions] = await Promise.all([
        apiRequest<ObservationPage>(`/api/v1/reconciliation/observations?${query.toString()}`),
        apiRequest<DecisionPage>(`/api/v1/reconciliation/decisions?offset=${decisionOffset}&limit=50`),
      ]);
      if (version === loadVersion.current) {
        const safeObservations = observations && Array.isArray(observations.items)
          ? {
            ...observations,
            items: observations.items
              .filter((item) => item && typeof item.id === 'string' && item.observation && typeof item.observation === 'object')
              .map((item) => ({ ...item, candidate_ids: Array.isArray(item.candidate_ids) ? item.candidate_ids : [] })),
          }
          : { revision: 0, total: 0, offset, limit: 50, items: [] };
        const safeDecisions = decisions && Array.isArray(decisions.items)
          ? { ...decisions, items: decisions.items.filter((item) => item && typeof item.id === 'string') }
          : { revision: safeObservations.revision, total: 0, items: [] };
        setObservationPage(safeObservations);
        setDecisionPage(safeDecisions);
        setSelectedIds((current) => current.filter((id) => safeObservations.items.some((item) => item.id === id)));
      }
    } catch (error) {
      if (version === loadVersion.current) setLoadError(newErrorMessage(error));
    } finally {
      if (version === loadVersion.current) setLoading(false);
    }
  }, [appliedSource, decisionOffset, offset, reviewStatus]);

  useEffect(() => {
    void refreshEvidence();
  }, [refreshEvidence, refreshToken]);

  async function searchAssets(nextOffset = 0) {
    const query = assetSearch.trim();
    setAssetSearchLoading(true);
    setAssetsError(null);
    try {
      const result = await apiRequest<{ total: number; items: AssetChoice[] }>(
        `/api/v1/reconciliation/assets?q=${encodeURIComponent(query)}&offset=${nextOffset}&limit=${assetPageSize}`,
      );
      setAssets(result.items);
      setAssetOffset(nextOffset);
      setAssetTotal(result.total);
    } catch (error) {
      setAssetsError(newErrorMessage(error));
    } finally {
      setAssetSearchLoading(false);
    }
  }

  async function openDetails(item: PersistentItem) {
    const requestVersion = ++detailRequestVersion.current;
    setDetail(null);
    setDetailError(null);
    try {
      const result = await apiRequest<ObservationDetail>(`/api/v1/reconciliation/observations/${encodeURIComponent(item.id)}`);
      if (requestVersion === detailRequestVersion.current) setDetail(result);
    } catch (error) {
      if (requestVersion === detailRequestVersion.current) setDetailError(newErrorMessage(error));
    }
  }

  function toggleSelection(id: string, checked: boolean) {
    setSelectedIds((current) => checked ? [...new Set([...current, id])] : current.filter((entry) => entry !== id));
  }

  function reviewDecision() {
    if (!observationPage || !reason.trim()) return;
    const selected = observationPage.items.filter((item) => selectedIds.includes(item.id));
    if (action !== 'undo' && action !== 'merge' && selected.length === 0) return;
    if ((action === 'assign' || action === 'merge') && !targetAssetId) return;
    if ((action === 'split' || action === 'merge') && !sourceAssetId) return;
    if (action === 'undo' && !undoDecision) return;
    const versions = Object.fromEntries(selected.map((item) => [item.id, item.version]));
    const payload: DecisionPayload = {
      request_key: requestKey(),
      expected_revision: observationPage.revision,
      reason: reason.trim(),
      action,
      observation_ids: selected.map((item) => item.id),
      expected_versions: versions,
    };
    if (action === 'assign' || action === 'merge') payload.target_asset_id = targetAssetId ?? undefined;
    if (action === 'split' || action === 'merge') payload.source_asset_id = sourceAssetId ?? undefined;
    if (action === 'undo' && undoDecision) payload.undo_decision_id = undoDecision.id;
    const target = assets.find((asset) => asset.id === targetAssetId);
    const source = assets.find((asset) => asset.id === sourceAssetId);
    const targetName = target ? assetDisplayName(target) : 'the selected asset';
    const sourceName = source ? assetDisplayName(source) : 'the selected asset';
    const consequence: Record<DecisionAction, string> = {
      assign: `This assigns the selected evidence to ${targetName}.`,
      create: 'This creates a separate provisional asset for the selected evidence.',
      reject: 'This removes the selected evidence from asset matching.',
      defer: 'This leaves the selected evidence open for a later review.',
      merge: `This moves all persistent evidence from ${sourceName} to ${targetName}. The asset records and scanner findings remain unchanged.`,
      split: `This moves only the selected evidence from ${sourceName} into a new provisional asset.`,
      undo: `This reverses “${undoDecision?.reason}” only if its affected evidence has not changed.`,
    };
    setDecisionError(null);
    setDecisionConflict(false);
    setPendingDecision({ payload, consequence: consequence[action] });
  }

  async function saveDecision() {
    if (!pendingDecision || decisionConflict) return;
    setSavingDecision(true);
    setDecisionError(null);
    try {
      const result = await apiRequest<{ id: string; revision: number; action: DecisionAction; changed_rows: number; replayed: boolean }>(
        '/api/v1/reconciliation/decisions',
        { method: 'POST', body: pendingDecision.payload },
      );
      setPendingDecision(null);
      setReason('');
      setSelectedIds([]);
      setDecisionOffset(0);
      setUndoDecision(null);
      setTargetAssetId(null);
      setSourceAssetId(null);
      await refreshEvidence();
      setDecisionError(`${humanize(result.action)} saved for ${result.changed_rows} evidence row(s).`);
    } catch (error) {
      const conflict = statusConflict(error);
      setDecisionConflict(conflict);
      setDecisionError(conflict
        ? 'This list changed while you were reviewing. Refresh evidence before deciding.'
        : newErrorMessage(error));
    } finally {
      setSavingDecision(false);
    }
  }

  function refreshAfterConflict() {
    setPendingDecision(null);
    setUndoDecision(null);
    setDecisionError(null);
    setDecisionConflict(false);
    setSelectedIds([]);
    void refreshEvidence();
  }

  const pageItems = observationPage?.items ?? [];
  const decisionItems = decisionPage?.items ?? [];
  const allPageSelected = pageItems.length > 0 && pageItems.every((item) => selectedIds.includes(item.id));
  const needsTarget = action === 'assign' || action === 'merge';
  const needsSource = action === 'merge' || action === 'split';
  const canReview = Boolean(
    reason.trim()
    && observationPage
    && (action === 'undo' ? undoDecision : action === 'merge' ? targetAssetId && sourceAssetId : selectedIds.length > 0)
    && (action !== 'assign' || targetAssetId)
    && (action !== 'split' || (
      sourceAssetId
      && selectedIds.length > 0
      && selectedIds.every((id) => observationPage.items.find((item) => item.id === id)?.asset_id === sourceAssetId)
    ))
    && (action !== 'merge' || sourceAssetId !== targetAssetId)
    && (action !== 'defer' || selectedIds.every((id) => observationPage.items.find((item) => item.id === id)?.asset_id === null))
    && (action !== 'create' || selectedIds.every((id) => observationPage.items.find((item) => item.id === id)?.asset_id === null)),
  );

  return (
    <Card className="vb-card" withBorder>
      <Stack>
        <div>
          <Title order={2} size="h4">Persistent evidence review</Title>
          <Text size="sm" c="dimmed">Review saved source evidence and record careful corrections.</Text>
        </div>
        <Alert color="blue" title="Evidence and scanner reports stay separate">
          Decisions change evidence assignments only. They do not edit scanner reports or resolve finding statuses.
        </Alert>
        {decisionError && !pendingDecision ? <Alert color="green">{decisionError}</Alert> : null}
        {decisionError && pendingDecision && !decisionConflict ? <Alert color="red" title="Decision was not saved">{decisionError}</Alert> : null}
        {loadError ? <Alert color="red" title="Could not load evidence">{loadError}</Alert> : null}
        <Group align="flex-end" wrap="wrap">
          <Select label="Review status" data={reviewOptions} value={reviewStatus} onChange={(value) => { setReviewStatus(value ?? 'open'); setOffset(0); }} />
          <TextInput label="Source filter" placeholder="For example, inventory" value={sourceFilter} onChange={(event) => setSourceFilter(event.currentTarget.value)} />
          <Button variant="default" onClick={() => { setOffset(0); setAppliedSource(sourceFilter); }}>Apply filters</Button>
          <Button variant="default" onClick={() => void refreshEvidence()} loading={loading}>Refresh evidence</Button>
        </Group>
        {pageItems.length ? (
          <Table.ScrollContainer minWidth={900}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th><Checkbox aria-label="Select all evidence on this page" checked={allPageSelected} onChange={(event) => setSelectedIds(event.currentTarget.checked ? pageItems.map((item) => item.id) : [])} /></Table.Th>
                  <Table.Th>Evidence</Table.Th><Table.Th>Source</Table.Th><Table.Th>State</Table.Th><Table.Th>Current asset</Table.Th><Table.Th>Possible match</Table.Th><Table.Th>Reason</Table.Th><Table.Th>Details</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {pageItems.map((item) => (
                  <Table.Tr key={item.id}>
                    <Table.Td><Checkbox aria-label={`Select evidence from ${identity(item)}`} checked={selectedIds.includes(item.id)} onChange={(event) => toggleSelection(item.id, event.currentTarget.checked)} /></Table.Td>
                    <Table.Td>
                      <Text fw={600}>{identity(item)}</Text>
                      {item.observation.kind ? <Text size="xs" c="dimmed">{humanize(item.observation.kind)}{item.observation.observed_at ? ` · ${formatDate(item.observation.observed_at, true)}` : ''}</Text> : null}
                      {item.observation.warnings?.length ? <Text size="xs" c="orange">{item.observation.warnings.join('; ')}</Text> : null}
                    </Table.Td>
                    <Table.Td>{[item.observation.provenance?.source, item.observation.provenance?.instance].filter(Boolean).join(' · ') || 'Unknown source'}</Table.Td>
                    <Table.Td><Badge color={item.review_status === 'open' ? 'orange' : item.review_status === 'assigned' ? 'green' : 'gray'}>{humanize(item.review_status)}</Badge></Table.Td>
                    <Table.Td>{item.asset_id ? <Text size="xs" c="dimmed">Current asset: {item.asset_name?.trim() || 'Name not available'}</Text> : '—'}</Table.Td>
                    <Table.Td>{item.candidate_ids.length ? `${item.candidate_ids.length} possible` : 'None'}</Table.Td>
                    <Table.Td>
                      {item.explanation ?? item.rule ?? 'No automatic match'}
                      {item.confidence != null ? <Text size="xs" c="dimmed">Rule score: {item.confidence.toFixed(2)}</Text> : null}
                    </Table.Td>
                    <Table.Td><Button size="xs" variant="subtle" aria-label={`Details for ${identity(item)}`} onClick={() => void openDetails(item)}>Details</Button></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        ) : loading ? (
          <Text c="dimmed">Loading evidence…</Text>
        ) : (
          <Text c="dimmed">No evidence matches these filters.</Text>
        )}
        <Group justify="space-between">
          <Text size="sm" c="dimmed">Showing {pageItems.length ? offset + 1 : 0}–{offset + pageItems.length} of {observationPage?.total ?? 0}</Text>
          <Group>
            <Button variant="default" disabled={offset <= 0 || loading} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous</Button>
            <Button variant="default" disabled={offset + 50 >= (observationPage?.total ?? 0) || loading} onClick={() => setOffset(offset + 50)}>Next</Button>
          </Group>
        </Group>

        <Card withBorder padding="sm">
          <Stack gap="sm">
            <Title order={3} size="h5">Record a decision</Title>
            <Text size="sm" c="dimmed">Selected evidence: {selectedIds.length}. Every change includes your reason.</Text>
            <Select label="Action" data={actionOptions} value={action} onChange={(value) => {
              const nextAction = (value ?? 'assign') as DecisionAction;
              setAction(nextAction);
              if (nextAction === 'merge' || nextAction === 'undo') setSelectedIds([]);
              setUndoDecision(null);
              setDecisionError(null);
            }} />
            {needsSource || needsTarget ? <Stack gap="xs">
              <Group align="flex-end" wrap="wrap">
              <TextInput label="Find assets by name or ID" placeholder="Leave blank to browse" value={assetSearch} onChange={(event) => {
                const value = event.currentTarget.value;
                setAssetSearch(value);
              }} />
              <Button variant="default" loading={assetSearchLoading} onClick={() => void searchAssets(0)}>{assetSearch.trim() ? 'Search assets' : 'Browse assets'}</Button>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">{assets.length ? `Showing ${assetOffset + 1}-${assetOffset + assets.length} of ${assetTotal} assets` : `${assetTotal} assets`}</Text>
                <Group gap="xs">
                  <Button size="xs" variant="default" disabled={assetOffset <= 0 || assetSearchLoading} onClick={() => void searchAssets(Math.max(0, assetOffset - assetPageSize))}>Previous assets</Button>
                  <Button size="xs" variant="default" disabled={assetOffset + assets.length >= assetTotal || assetSearchLoading} onClick={() => void searchAssets(assetOffset + assetPageSize)}>Next assets</Button>
                </Group>
              </Group>
            </Stack> : null}
            {needsSource ? <Select
              label="Source asset"
              clearable
              data={assets.map((asset) => ({ value: asset.id, label: assetChoiceLabel(asset) }))}
              value={sourceAssetId}
              onChange={setSourceAssetId}
              nothingFoundMessage={assetsError ?? 'Search by asset name'}
            /> : null}
            {needsTarget ? <Select
              label="Target asset"
              clearable
              data={assets.map((asset) => ({ value: asset.id, label: assetChoiceLabel(asset) }))}
              value={targetAssetId}
              onChange={setTargetAssetId}
              nothingFoundMessage={assetsError ?? 'Search by asset name'}
            /> : null}
            {action === 'undo' ? (
              <Select
                label="Decision to undo"
                data={decisionItems.filter((entry) => entry.reversible && !entry.undone).map((entry) => ({ value: entry.id, label: `${humanize(entry.action)} · ${entry.reason}` }))}
                value={undoDecision?.id ?? null}
                onChange={(value) => setUndoDecision(decisionItems.find((entry) => entry.id === value) ?? null)}
                nothingFoundMessage="No reversible decisions on this page"
              />
            ) : null}
            <Textarea label="Reason" value={reason} minRows={2} onChange={(event) => setReason(event.currentTarget.value)} required />
            {assetsError ? <Text size="sm" c="red">Could not search assets: {assetsError}</Text> : null}
            {action === 'merge' ? <Alert color="orange" title="Merge consequence">All current persistent evidence on the source asset moves to the target. Asset records and scanner findings stay unchanged.</Alert> : null}
            {action === 'split' ? <Alert color="orange" title="Split consequence">Only selected evidence on the source asset moves to a new provisional asset.</Alert> : null}
            {(action === 'create' || action === 'defer') && selectedIds.some((id) => observationPage?.items.find((item) => item.id === id)?.asset_id) ? (
              <Alert color="orange">Create and defer apply only to unassigned evidence. Use correction or split for assigned evidence.</Alert>
            ) : null}
            <Group justify="flex-end">
              <Button disabled={!canReview || Boolean(loadError)} onClick={reviewDecision}>Review action</Button>
            </Group>
          </Stack>
        </Card>

        <Card withBorder padding="sm">
          <Stack gap="sm">
            <Group justify="space-between"><Title order={3} size="h5">Decision history</Title><Text size="sm" c="dimmed">{decisionPage?.total ?? 0} total</Text></Group>
            {decisionItems.length ? (
              <Table.ScrollContainer minWidth={650}>
                <Table striped>
                  <Table.Thead><Table.Tr><Table.Th>Action</Table.Th><Table.Th>Reason</Table.Th><Table.Th>By</Table.Th><Table.Th>When</Table.Th><Table.Th>Undo</Table.Th></Table.Tr></Table.Thead>
                  <Table.Tbody>{decisionItems.map((entry) => (
                    <Table.Tr key={entry.id}>
                      <Table.Td>{humanize(entry.action)}</Table.Td><Table.Td>{entry.reason}</Table.Td><Table.Td>{entry.actor_user_id ? 'Administrator' : 'System'}</Table.Td><Table.Td>{formatDate(entry.occurred_at, true)}</Table.Td>
                      <Table.Td>{entry.reversible && !entry.undone ? <Button size="xs" variant="subtle" onClick={() => {
                        setAction('undo');
                        setSelectedIds([]);
                        setUndoDecision(entry);
                        setReason('');
                        setDecisionError(null);
                      }}>Undo</Button> : entry.undone ? 'Undone' : '—'}</Table.Td>
                    </Table.Tr>
                  ))}</Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            ) : <Text size="sm" c="dimmed">No decisions have been recorded.</Text>}
          </Stack>
        </Card>
        <Group justify="space-between">
          <Text size="sm" c="dimmed">Decision {decisionItems.length ? decisionOffset + 1 : 0}–{decisionOffset + decisionItems.length} of {decisionPage?.total ?? 0}</Text>
          <Group>
            <Button variant="default" disabled={decisionOffset <= 0 || loading} onClick={() => setDecisionOffset(Math.max(0, decisionOffset - 50))}>Previous decisions</Button>
            <Button variant="default" disabled={decisionOffset + 50 >= (decisionPage?.total ?? 0) || loading} onClick={() => setDecisionOffset(decisionOffset + 50)}>Next decisions</Button>
          </Group>
        </Group>

        {detailError ? <Alert color="red" title="Could not load evidence details">{detailError}</Alert> : null}
        {detail ? (
          <Card withBorder padding="sm">
            <Stack gap="xs">
              <Group justify="space-between"><Title order={3} size="h5">Evidence details: {identity(detail)}</Title><Button size="xs" variant="subtle" onClick={() => setDetail(null)}>Close</Button></Group>
              <Text size="sm">Source: {[detail.observation.provenance?.source, detail.observation.provenance?.instance].filter(Boolean).join(' · ') || 'Unknown'}</Text>
              <Text size="sm">File: {detail.locators[0]?.filename ?? detail.observation.provenance?.filename ?? 'Not available'}</Text>
              <Text size="sm">Record: {detail.locators[0]?.record_number ?? detail.observation.provenance?.record_number ?? 'Not available'}</Text>
              {detail.observation.provenance?.file_sha256 ? <Text size="xs" c="dimmed" className="vb-mono">File hash: {detail.observation.provenance.file_sha256}</Text> : null}
              {detail.observation.warnings?.length ? <Alert color="orange" title="Evidence notes">{detail.observation.warnings.join('; ')}</Alert> : null}
              {detail.observation.vulnerability ? <>
                <Text fw={600}>Vulnerability evidence</Text>
                <Text size="sm">Vulnerability: {detail.observation.vulnerability.vulnerability_id || 'Not provided'}</Text>
                <Text size="sm">Native status: {detail.observation.vulnerability.native_status || 'Not provided'}</Text>
                <Text size="sm">CVEs: {detail.observation.vulnerability.cves?.length ? detail.observation.vulnerability.cves.join(', ') : 'None provided'}</Text>
              </> : null}
              {detail.observation.coverage ? <>
                <Text fw={600}>Coverage evidence</Text>
                <Text size="sm">Coverage outcome: {detail.observation.coverage.outcome ? humanize(detail.observation.coverage.outcome) : 'Not provided'}</Text>
                <Text size="sm">Full-scope check: {yesNoUnknown(detail.observation.coverage.complete)}</Text>
                <Text size="sm">Authenticated check: {yesNoUnknown(detail.observation.coverage.authenticated)}</Text>
              </> : null}
              <Text fw={600}>Saved copies ({detail.locator_total})</Text>
              {detail.locators.length ? detail.locators.map((locator) => <Text size="sm" key={`${locator.batch_id}-${locator.record_number}`}>{locator.filename} · record {locator.record_number} · {formatDate(locator.imported_at, true)}</Text>) : <Text size="sm" c="dimmed">No source copies are available.</Text>}
              <Text fw={600}>Assignment history ({detail.history_total})</Text>
              {detail.history.length ? detail.history.map((entry) => <Text size="sm" key={`${entry.version}-${entry.occurred_at}`}>Version {entry.version} · {humanize(entry.review_status)} · {entry.asset_id ? 'Assigned to an asset' : 'Unassigned'} · {formatDate(entry.occurred_at, true)}</Text>) : <Text size="sm" c="dimmed">No assignment history is available.</Text>}
            </Stack>
          </Card>
        ) : null}

        <Modal opened={Boolean(pendingDecision)} onClose={() => { if (!savingDecision) setPendingDecision(null); }} title="Review this decision">
          <Stack>
            <Text>{pendingDecision?.consequence}</Text>
            {pendingDecision ? <Text size="sm" c="dimmed">Reason: {pendingDecision.payload.reason}</Text> : null}
            {decisionError && pendingDecision ? <Alert color="red" title={decisionConflict ? 'Refresh before deciding' : 'Decision was not saved'}>{decisionError}</Alert> : null}
            {decisionConflict ? <Button variant="default" onClick={refreshAfterConflict}>Refresh evidence</Button> : null}
            <Group justify="flex-end">
              <Button variant="default" disabled={savingDecision} onClick={() => setPendingDecision(null)}>Cancel</Button>
              <Button disabled={decisionConflict} loading={savingDecision} onClick={() => void saveDecision()}>Save decision</Button>
            </Group>
          </Stack>
        </Modal>
      </Stack>
    </Card>
  );
}
