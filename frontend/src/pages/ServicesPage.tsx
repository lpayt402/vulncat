import { useRef, useState } from 'react';
import {
  Alert, Badge, Button, Checkbox, FileInput, Group, Modal, NativeSelect, Paper,
  SimpleGrid, Stack, Table, Tabs, Text, Textarea, TextInput, Title,
} from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { IconAlertTriangle, IconDownload, IconRefresh, IconTopologyStar } from '@tabler/icons-react';
import { Link } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { ApiError, apiRequest, downloadFromApi, toQueryString } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { formatDate } from '../utils/format';

interface Provenance {
  source?: string;
  instance?: string;
  observed_at?: string | null;
  imported_at?: string | null;
  time_meaning?: string;
}
interface ExposureNode {
  id: string;
  kind: string;
  label: string;
  native_id: string;
  source: string;
  instance: string;
  asset_id?: string | null;
  asset_name?: string | null;
  protocol?: string | null;
  port?: number | null;
  dns_name?: string | null;
  sni?: string | null;
  ip_address?: string | null;
  network_scope?: string | null;
  facts: Record<string, unknown>;
  provenance?: Provenance;
  fact_summary?: { fact_count: number; distinct_fact_count: number; has_disagreement: boolean; stale_fact_count: number; latest_observed_at: string | null };
  exposure_counts?: { inventory: number; vulnerability: number; coverage: number };
}
interface Page<T> { revision: number; total: number; offset: number; limit: number; items: T[] }
interface Observation {
  observation_id: string;
  observation_kind: string;
  vulnerability_id?: string | null;
  native_status?: string | null;
  coverage_outcome?: string | null;
  source: string;
  instance: string;
  observed_at?: string | null;
  imported_at?: string | null;
  age_days?: number | null;
  time_meaning: string;
  time_warning?: string | null;
  asset_id?: string | null;
  asset_name?: string | null;
  node_id?: string | null;
  node_kind?: string | null;
  node_label?: string | null;
  service_id?: string | null;
  service_label?: string | null;
  network_scope?: string | null;
  protocol?: string | null;
  port?: number | null;
  dns_name?: string | null;
  sni?: string | null;
  attribution_status: string;
  attribution_reason: string;
  attribution_id?: string | null;
  attribution_version?: number | null;
  evidence: Record<string, unknown>;
}
interface Report extends Page<Observation> { counts: { inventory: number; vulnerability: number; coverage: number } }
interface Relationship { id: string; kind: string; from_node_id: string; to_node_id: string; from_node_label?: string; to_node_label?: string; source: string; instance: string; evidence: Record<string, unknown>; provenance?: Provenance }
interface Graph { revision: number; total: number; offset: number; limit: number; nodes: ExposureNode[]; relationships: Relationship[]; relationship_total: number; relationship_offset: number; relationship_limit: number }
interface Change { entity_type?: string; entity_id?: string; before: unknown; after: unknown }
interface Decision { id: string; decision_id: string; action: string; reason: string; occurred_at: string; undo_of_id?: string | null; changes: Change[]; undoable: boolean; undo_block_reason?: string | null }
interface Preview { revision: number; preview_token: string; payload_sha256: string; changes: Change[]; counts: Record<string, number>; warnings: string[] }
interface ReviewedPreview { result: Preview; graph: object; generation: number; requestKey: string }
interface FactDetail { revision: number; node: ExposureNode; facts: Array<{ id: string; observed_at: string | null; imported_at: string; payload: unknown; provenance: Provenance }>; fact_total: number }
interface Asset { id: string; canonical_hostname?: string | null; display_name?: string | null }

const NODE_PAGE_SIZE = 20;
const REPORT_PAGE_SIZE = 25;
const kindLabels: Record<string, string> = { host: 'Host', device: 'Device', load_balancer: 'Load balancer', vip: 'VIP', service: 'Service', endpoint: 'Endpoint' };
const relationLabels: Record<string, string> = { endpoint_of: 'Endpoint of', backed_by: 'Backed by', routes_to: 'Routes to', hosted_on: 'Hosted on', management_of: 'Management of' };
const timeLabels: Record<string, string> = { source_observed: 'Source observed', last_logon: 'Last logon', record_updated: 'Record updated', export_snapshot: 'Export snapshot', export_generated: 'Export generated', unknown: 'Timestamp (meaning unknown)' };
const human = (value?: string | null) => value ? value.replaceAll('_', ' ').replace(/^./, (letter) => letter.toUpperCase()) : 'Unknown';

function Paging({ offset, total, limit, count, name, busy, onChange }: { offset: number; total: number; limit: number; count: number; name: string; busy?: boolean; onChange: (offset: number) => void }) {
  return <Group justify="space-between" mt="md">
    <Text size="xs" c="dimmed" aria-live="polite">{count ? `${offset + 1}–${offset + count} of ${total} ${name}` : `0 of ${total} ${name}`}</Text>
    <Group gap="xs">
      <Button size="xs" variant="default" disabled={offset === 0 || busy} onClick={() => onChange(Math.max(0, offset - limit))}>Previous {name}</Button>
      <Button size="xs" variant="default" disabled={offset + limit >= total || busy} onClick={() => onChange(offset + limit)}>Next {name}</Button>
    </Group>
  </Group>;
}

function EvidenceDetails({ value }: { value: unknown }) {
  return <details><summary>Evidence details</summary><pre className="vb-evidence-details">{JSON.stringify(value, null, 2)}</pre></details>;
}

function FactValues({ facts }: { facts: Record<string, unknown> }) {
  return <dl className="vb-fact-values">{Object.entries(facts).map(([key, value]) => <div key={key}><dt>{key === 'os' ? 'Operating system' : human(key)}</dt><dd>{typeof value === 'string' || typeof value === 'number' ? String(value) : JSON.stringify(value)}</dd></div>)}</dl>;
}

function ObservationsTable({ report, all, onReview }: { report: Report; all?: boolean; onReview?: (row: Observation) => void }) {
  return <div className="vb-table-wrap" tabIndex={0} role="region" aria-label="Exposure table, scroll horizontally for more columns">
    <Table className="vb-table" verticalSpacing="md">
      <caption>Exposure observations — {all ? 'all targets, including unassigned evidence' : 'direct attributions and explicit service endpoints'}</caption>
      <Table.Thead><Table.Tr>{['Observation', 'Source & time', 'Target & scope', 'Attribution', 'Evidence'].map((label) => <Table.Th scope="col" key={label}>{label}</Table.Th>)}</Table.Tr></Table.Thead>
      <Table.Tbody>{report.items.map((row) => <Table.Tr key={`${row.observation_id}:${row.node_id ?? 'unassigned'}`}>
        <Table.Td><Stack gap={4}>
          <Badge variant="outline" color={row.observation_kind === 'vulnerability' ? 'orange' : row.observation_kind === 'coverage' ? 'blue' : 'gray'}>{human(row.observation_kind)}</Badge>
          <Text size="sm" fw={600}>{row.vulnerability_id ?? (row.observation_kind === 'coverage' ? human(row.coverage_outcome) : 'Inventory evidence')}</Text>
          {row.native_status ? <Text size="xs">Source status: {row.native_status}</Text> : null}
          <Text size="xs" c="dimmed" className="vb-mono">{row.observation_id}</Text>
        </Stack></Table.Td>
        <Table.Td><Stack gap={4} miw={170}>
          <Text size="sm">{row.source} · {row.instance}</Text>
          <Text size="xs">{row.observed_at ? `${timeLabels[row.time_meaning] ?? 'Timestamp (meaning unknown)'}: ${formatDate(row.observed_at)}` : 'Observation time unknown'}</Text>
          <Text size="xs" c="dimmed">Imported: {formatDate(row.imported_at)}</Text>
          <Text size="xs">{row.age_days != null ? `${row.age_days} days old` : 'Age unknown'} · {human(row.time_meaning)}</Text>
          {row.time_warning ? <Text size="xs">Time warning: {row.time_warning}</Text> : null}
        </Stack></Table.Td>
        <Table.Td><Stack gap={4} miw={150}>
          <Text size="sm">{row.node_label ?? 'Unassigned target'} · {human(row.node_kind)}</Text>
          {row.service_label ? <Text size="xs">Service: {row.service_label}</Text> : null}
          <Text size="xs">Scope: {row.network_scope ?? 'Unknown'}</Text>
          {row.protocol || row.port != null ? <Text size="xs">{row.protocol ?? 'Protocol unknown'} / {row.port ?? 'Port unknown'}</Text> : null}
          {row.dns_name ? <Text size="xs">DNS: {row.dns_name}</Text> : null}
          {row.sni ? <Text size="xs">SNI: {row.sni}</Text> : null}
          {row.asset_id ? <Text component={Link} className="vb-text-link" size="xs" to={`/hosts/${row.asset_id}`}>Host: {row.asset_name ?? row.asset_id}</Text> : null}
        </Stack></Table.Td>
        <Table.Td><Stack gap={4} miw={170}>
          <Badge variant="outline" color={row.attribution_status === 'review_needed' ? 'orange' : 'gray'}>{human(row.attribution_status)}</Badge>
          <Text size="sm">{row.attribution_reason || 'No attribution explanation provided.'}</Text>
          {onReview ? <Button size="xs" variant="default" onClick={() => onReview(row)}>Review attribution for {row.vulnerability_id ?? row.observation_id}</Button> : null}
        </Stack></Table.Td>
        <Table.Td><EvidenceDetails value={row.evidence} /></Table.Td>
      </Table.Tr>)}</Table.Tbody>
    </Table>
  </div>;
}

export function ServicesPage() {
  const { user } = useAuth();
  const administrator = user?.role === 'administrator';
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState('');
  const [nodeOffset, setNodeOffset] = useState(0);
  const [selected, setSelected] = useState<ExposureNode | null>(null);
  const [allObservations, setAllObservations] = useState(false);
  const [tab, setTab] = useState<string | null>('exposure');
  const [observationKind, setObservationKind] = useState('');
  const [reportOffset, setReportOffset] = useState(0);
  const [graphOffset, setGraphOffset] = useState(0);
  const [relationshipOffset, setRelationshipOffset] = useState(0);
  const [graphAll, setGraphAll] = useState(false);
  const [historyOffset, setHistoryOffset] = useState(0);
  const [downloadFormat, setDownloadFormat] = useState('csv');
  const [downloadError, setDownloadError] = useState<unknown>(null);
  const [downloading, setDownloading] = useState(false);
  const [draft, setDraft] = useState('');
  const draftGeneration = useRef(0);
  const [reviewed, setReviewed] = useState<ReviewedPreview | null>(null);
  const [reason, setReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [fileError, setFileError] = useState('');
  const [success, setSuccess] = useState('');
  const [undoTarget, setUndoTarget] = useState<Decision | null>(null);
  const [undoReason, setUndoReason] = useState('');
  const [undoConfirmed, setUndoConfirmed] = useState(false);
  const [assetSearch, setAssetSearch] = useState('');
  const [assetQuery, setAssetQuery] = useState<string | null>(null);
  const [assetOffset, setAssetOffset] = useState(0);
  const [assetId, setAssetId] = useState('');
  const [mappingRow, setMappingRow] = useState<Observation | null>(null);
  const [mappingSearch, setMappingSearch] = useState('');
  const [mappingQuery, setMappingQuery] = useState('');
  const [mappingOffset, setMappingOffset] = useState(0);
  const [mappingNodeId, setMappingNodeId] = useState('');
  const [mappingStatus, setMappingStatus] = useState('attributed');
  const [factHistoryOpen, setFactHistoryOpen] = useState(false);
  const [factOffset, setFactOffset] = useState(0);
  const undoRequestKey = useRef('');

  const nodes = useQuery({ queryKey: ['exposure', 'nodes', query, kind, nodeOffset], queryFn: ({ signal }) => apiRequest<Page<ExposureNode>>(`/api/v1/exposure/nodes${toQueryString({ q: query, kind, offset: nodeOffset, limit: NODE_PAGE_SIZE })}`, { signal }) });
  const report = useQuery({ queryKey: ['exposure', 'report', selected?.id, observationKind, reportOffset], enabled: Boolean(selected) || allObservations, queryFn: ({ signal }) => apiRequest<Report>(`/api/v1/exposure/report${toQueryString({ node_id: selected?.id, observation_kind: observationKind, offset: reportOffset, limit: REPORT_PAGE_SIZE })}`, { signal }) });
  const graph = useQuery({ queryKey: ['exposure', 'graph', selected?.id, graphAll, graphOffset, relationshipOffset], enabled: (Boolean(selected) || graphAll) && tab === 'relationships', queryFn: ({ signal }) => apiRequest<Graph>(`/api/v1/exposure/graph${toQueryString({ node_id: graphAll ? undefined : selected?.id, offset: graphOffset, limit: NODE_PAGE_SIZE, relationship_offset: relationshipOffset, relationship_limit: NODE_PAGE_SIZE })}`, { signal }) });
  const history = useQuery({ queryKey: ['exposure', 'history', selected?.id, historyOffset], enabled: tab === 'history', queryFn: ({ signal }) => apiRequest<Page<Decision>>(`/api/v1/exposure/history${toQueryString({ node_id: selected?.id, offset: historyOffset, limit: NODE_PAGE_SIZE })}`, { signal }) });
  const assets = useQuery({ queryKey: ['exposure', 'asset-lookup', assetQuery, assetOffset], enabled: administrator && assetQuery !== null && tab === 'import', queryFn: ({ signal }) => apiRequest<Page<Asset>>(`/api/v1/reconciliation/assets${toQueryString({ q: assetQuery, offset: assetOffset, limit: NODE_PAGE_SIZE })}`, { signal }) });
  const mappingNodes = useQuery({ queryKey: ['exposure', 'mapping-nodes', mappingQuery, mappingOffset], enabled: administrator && Boolean(mappingRow), queryFn: ({ signal }) => apiRequest<Page<ExposureNode>>(`/api/v1/exposure/nodes${toQueryString({ q: mappingQuery, offset: mappingOffset, limit: NODE_PAGE_SIZE })}`, { signal }) });
  const factHistory = useQuery({ queryKey: ['exposure', 'fact-history', selected?.id, factOffset], enabled: Boolean(selected) && factHistoryOpen, queryFn: ({ signal }) => apiRequest<FactDetail>(`/api/v1/exposure/nodes/${selected?.id}${toQueryString({ fact_offset: factOffset, fact_limit: NODE_PAGE_SIZE })}`, { signal }) });

  function editDraft(value: string) {
    draftGeneration.current += 1;
    setDraft(value); setReviewed(null); setConfirmed(false); setSuccess(''); setFileError('');
    preview.reset(); apply.reset();
  }
  const preview = useMutation({
    mutationFn: ({ graph }: { graph: object; generation: number }) => apiRequest<Preview>('/api/v1/exposure/preview', { method: 'POST', body: { graph } }),
    onSuccess: (result, variables) => { if (variables.generation === draftGeneration.current) { setReviewed({ result, ...variables, requestKey: crypto.randomUUID() }); setConfirmed(false); } },
  });
  const apply = useMutation({
    mutationFn: () => {
      if (!administrator || !reviewed || !reviewed.result.preview_token || !Number.isFinite(reviewed.result.revision) || reviewed.generation !== draftGeneration.current || !confirmed || !reason.trim()) throw new Error('Review the current changes and confirm them first.');
      return apiRequest<{ revision: number; decision_id: string }>('/api/v1/exposure/apply', { method: 'POST', body: { graph: reviewed.graph, preview_token: reviewed.result.preview_token, expected_revision: reviewed.result.revision, reason: reason.trim(), request_key: reviewed.requestKey, confirmed: true } });
    },
    onSuccess: (result) => { setSuccess(`Changes saved. Change ${result.decision_id} is available in history.`); setReviewed(null); setConfirmed(false); setMappingRow(null); void queryClient.invalidateQueries({ queryKey: ['exposure'] }); },
    onError: (error) => { if (error instanceof ApiError && error.status === 409) { draftGeneration.current += 1; setReviewed(null); setConfirmed(false); } },
  });
  const undo = useMutation({
    mutationFn: () => {
      if (!administrator || !undoTarget?.undoable || !undoConfirmed || !undoReason.trim() || history.data?.revision == null) throw new Error('Review and confirm the selected change before undoing it.');
      return apiRequest('/api/v1/exposure/undo', { method: 'POST', body: { decision_id: undoTarget.decision_id, expected_revision: history.data.revision, reason: undoReason.trim(), request_key: undoRequestKey.current, confirmed: true } });
    },
    onSuccess: () => { setUndoTarget(null); setSuccess('The selected connection change was undone.'); void queryClient.invalidateQueries({ queryKey: ['exposure'] }); },
  });

  function chooseNode(node: ExposureNode) {
    setSelected(node); setAllObservations(false); setGraphAll(false); setReportOffset(0); setGraphOffset(0); setRelationshipOffset(0); setHistoryOffset(0); setDownloadError(null); setFactHistoryOpen(false); setFactOffset(0);
  }
  function refresh() {
    draftGeneration.current += 1; setReviewed(null); setConfirmed(false);
    void queryClient.invalidateQueries({ queryKey: ['exposure'] });
  }
  async function loadFile(file: File | null) {
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) { setFileError('Choose a JSON file smaller than 5 MB.'); return; }
    const generation = ++draftGeneration.current;
    setReviewed(null); setConfirmed(false);
    try { const value = await file.text(); if (generation === draftGeneration.current) editDraft(value); }
    catch { setFileError('The file could not be read. Paste its JSON below or choose it again.'); }
  }
  function previewDraft() {
    setFileError(''); setSuccess('');
    try {
      const parsed = JSON.parse(draft) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Connections must be a JSON object.');
      preview.mutate({ graph: parsed, generation: draftGeneration.current });
    } catch (error) { setFileError(error instanceof SyntaxError ? 'The JSON could not be read. Check its brackets, commas, and quotes.' : (error as Error).message); }
  }
  async function downloadPage() {
    if ((!selected && !allObservations) || !report.data) return;
    setDownloading(true); setDownloadError(null);
    try { await downloadFromApi(`/api/v1/exposure/report/export${toQueryString({ format: downloadFormat, node_id: selected?.id, observation_kind: observationKind, offset: reportOffset, limit: REPORT_PAGE_SIZE })}`); }
    catch (error) { setDownloadError(error); }
    finally { setDownloading(false); }
  }
  const currentNode = nodes.data?.items.find((node) => node.id === selected?.id) ?? selected;
  const graphNodeName = (id: string) => graph.data?.nodes.find((node) => node.id === id)?.label ?? (id === selected?.id ? selected.label : `Node outside this page (${id})`);
  function invalidateReview() { draftGeneration.current += 1; setReviewed(null); setConfirmed(false); preview.reset(); apply.reset(); }
  function openMapping(row: Observation) {
    invalidateReview(); setMappingRow(row); setMappingNodeId(''); setMappingStatus(row.attribution_status === 'attributed' ? 'attributed' : 'review_needed'); setReason(''); setMappingSearch(''); setMappingQuery(''); setMappingOffset(0);
  }
  function previewMapping() {
    if (!mappingRow || (mappingStatus === 'attributed' && !mappingNodeId) || !reason.trim()) return;
    const attribution = { observation_id: mappingRow.observation_id, node_ref: mappingStatus === 'attributed' ? mappingNodeId : null, status: mappingStatus, reason: reason.trim(), ...(mappingRow.attribution_version != null ? { expected_version: mappingRow.attribution_version } : {}) };
    const payload = { source: 'analyst', instance: 'manual-review', intent: 'manual_correction', time_meaning: 'unknown', nodes: [], relationships: [], attributions: [attribution] };
    preview.mutate({ graph: payload, generation: draftGeneration.current });
  }
  function reviewedControls(attribution = false) {
    return reviewed ? <>
      <Title order={3} size="h5">Review proposed changes</Title><Text size="sm">{reviewed.result.changes.length} changes · {Object.entries(reviewed.result.counts).map(([name, count]) => `${count} ${name}`).join(' · ')}</Text>
      {reviewed.result.warnings.map((warning, index) => <Alert color="orange" key={index}>{warning}</Alert>)}<EvidenceDetails value={reviewed.result.changes} />
      <Text size="xs" c="dimmed">Reviewed at revision {reviewed.result.revision}. A changed inventory requires another preview.</Text>
      {!attribution ? <TextInput label="Reason for this change" value={reason} onChange={(event) => setReason(event.currentTarget.value)} disabled={apply.isPending} required /> : null}
      <Checkbox label={attribution ? 'I reviewed this attribution and want to save it.' : 'I reviewed these connection changes and want to save them.'} checked={confirmed} onChange={(event) => setConfirmed(event.currentTarget.checked)} disabled={apply.isPending} />
      <Button onClick={() => apply.mutate()} disabled={!confirmed || !reason.trim()} loading={apply.isPending}>{attribution ? 'Apply reviewed attribution' : 'Apply reviewed connections'}</Button>
    </> : null;
  }

  return <>
    <PageHeader title="Services & exposure" description="Review observations by host, device, service or listener. Service connections and finding attribution are recorded separately." actions={<Button variant="default" leftSection={<IconRefresh size={16} />} onClick={refresh}>Refresh exposure</Button>} />
    <Alert color="blue" icon={<IconTopologyStar size={18} />} mb="lg">A VIP or reverse proxy can serve several backends. Its findings stay on their observed target until evidence supports another attribution. A shared private IP is meaningful only within its network scope.</Alert>
    <Tabs value={tab} onChange={setTab} className="vb-exposure-tabs" keepMounted={false}>
      <Tabs.List mb="lg"><Tabs.Tab value="exposure">Exposure</Tabs.Tab><Tabs.Tab value="relationships">Relationships</Tabs.Tab><Tabs.Tab value="history">Change history</Tabs.Tab>{administrator ? <Tabs.Tab value="import">Import connections</Tabs.Tab> : null}</Tabs.List>
      {success ? <Alert color="blue" mb="md" role="status">{success}</Alert> : null}
      {tab !== 'import' ? <div className="vb-exposure-layout">
        <Paper className="vb-card" p="md"><Stack gap="sm">
          <Title order={2} size="h4">Choose a target</Title>
          <Button variant="default" onClick={() => { setSelected(null); setAllObservations(true); setReportOffset(0); setTab('exposure'); }}>Review all observations</Button>
          <form onSubmit={(event) => { event.preventDefault(); setQuery(search.trim()); setNodeOffset(0); }}>
            <Stack gap="sm"><TextInput label="Find nodes" placeholder="Name, address, or source identifier" value={search} onChange={(event) => setSearch(event.currentTarget.value)} /><NativeSelect label="Node kind" value={kind} onChange={(event) => { setKind(event.currentTarget.value); setNodeOffset(0); }} data={[{ value: '', label: 'All kinds' }, ...Object.entries(kindLabels).map(([value, label]) => ({ value, label }))]} /><Button type="submit" variant="default">Search nodes</Button></Stack>
          </form>
          {nodes.isPending ? <LoadingState label="Loading nodes." /> : nodes.isError ? <ErrorState error={nodes.error} /> : <>
            {nodes.data.items.length ? nodes.data.items.map((node) => <button key={node.id} className="vb-node-choice" type="button" aria-label={`Select ${node.label} (${kindLabels[node.kind] ?? human(node.kind)}, ID ${node.id})`} aria-pressed={selected?.id === node.id} onClick={() => chooseNode(node)}>
              <span className="vb-node-label">{node.label}</span><span className="vb-node-meta">{kindLabels[node.kind] ?? human(node.kind)} · {node.network_scope ?? 'Scope unknown'}</span><span className="vb-node-meta">{node.ip_address ?? node.dns_name ?? node.native_id}</span><span className="vb-node-meta">{node.source} · {node.instance} · ID {node.id}</span>
              {node.fact_summary?.has_disagreement ? <span className="vb-node-meta">Conflicting evidence</span> : null}
            </button>) : <Text size="sm">No nodes match this search.</Text>}
            <Paging name="nodes" offset={nodeOffset} total={nodes.data.total} count={nodes.data.items.length} limit={NODE_PAGE_SIZE} busy={nodes.isFetching} onChange={setNodeOffset} />
          </>}
          {selected || allObservations ? <Button variant="subtle" onClick={() => { setSelected(null); setAllObservations(false); setHistoryOffset(0); }}>Clear selected target</Button> : null}
        </Stack></Paper>
        <Stack miw={0}>
          {currentNode ? <Paper className="vb-card vb-context" p="lg"><Stack gap="sm">
            <Group justify="space-between"><Title order={2} size="h3">{currentNode.label}</Title><Badge variant="outline">{kindLabels[currentNode.kind] ?? human(currentNode.kind)}</Badge></Group>
            <Text size="sm">{currentNode.source} · {currentNode.instance} · Scope: {currentNode.network_scope ?? 'Unknown'}</Text>
            <Text size="xs" c="dimmed">Observed: {formatDate(currentNode.provenance?.observed_at)} · Imported: {formatDate(currentNode.provenance?.imported_at)} · {human(currentNode.provenance?.time_meaning)}</Text>
            <Text size="xs" className="vb-mono">ID: {currentNode.id} · Source ID: {currentNode.native_id}</Text>
            {currentNode.protocol || currentNode.port != null || currentNode.dns_name || currentNode.sni ? <Text size="sm">{currentNode.protocol ?? 'Protocol unknown'} / {currentNode.port ?? 'Port unknown'} · DNS: {currentNode.dns_name ?? 'Unknown'} · SNI: {currentNode.sni ?? 'Unknown'}</Text> : null}
            {currentNode.asset_id ? <Text component={Link} to={`/hosts/${currentNode.asset_id}`} className="vb-text-link" size="sm">Open host: {currentNode.asset_name ?? currentNode.asset_id}</Text> : null}
            {currentNode.exposure_counts ? <Text size="sm">{currentNode.exposure_counts.vulnerability} vulnerability observations · {currentNode.exposure_counts.coverage} coverage observations · {currentNode.exposure_counts.inventory} inventory observations</Text> : null}
            {currentNode.fact_summary?.has_disagreement ? <Alert color="orange" icon={<IconAlertTriangle size={18} />}>Conflicting evidence: sources disagree about this target. Review their observations before choosing which fact to trust.</Alert> : null}
            {currentNode.fact_summary?.stale_fact_count ? <Text size="sm">{currentNode.fact_summary.stale_fact_count} older fact observations retained. They may describe an earlier state.</Text> : null}
            {Object.keys(currentNode.facts ?? {}).length ? <FactValues facts={currentNode.facts} /> : null}
            <Button variant="default" size="xs" onClick={() => { setFactOffset(0); setFactHistoryOpen(true); }}>Review fact history</Button>
          </Stack></Paper> : null}
          <Tabs.Panel value="exposure">
            {!selected && !allObservations ? <EmptyState title="Choose a node to inspect its exposure." message="Select an explicit target from the list. Findings, coverage, timestamps, and uncertain assignments will appear here." /> : <Paper className="vb-card" p="lg"><Stack>
              <Group justify="space-between"><Title order={2} size="h4">Observed exposure</Title><NativeSelect label="Observation kind" value={observationKind} onChange={(event) => { setObservationKind(event.currentTarget.value); setReportOffset(0); }} data={[{ value: '', label: 'All observations' }, { value: 'vulnerability', label: 'Vulnerabilities' }, { value: 'coverage', label: 'Coverage' }, { value: 'inventory', label: 'Inventory' }]} /></Group>
              {report.isPending ? <LoadingState label="Loading exposure observations." /> : report.isError ? <ErrorState error={report.error} /> : report.data ? <>
                <Text size="sm">{report.data.counts.vulnerability} vulnerability observations · {report.data.counts.coverage} coverage observations · {report.data.counts.inventory} inventory observations</Text>
                <Alert color="gray">Zero vulnerability observations alone do not establish safety. Check coverage, reachability, authentication, scope, and observation time.</Alert>
                {report.data.items.length ? <ObservationsTable report={report.data} all={allObservations} onReview={administrator ? openMapping : undefined} /> : <EmptyState title={observationKind ? 'No observations of this kind.' : 'Coverage unknown for this node.'} message="No matching evidence is available in this view. Confirm that the target was reachable and included in a recent assessment." />}
                <Paging name="observations" offset={reportOffset} total={report.data.total} count={report.data.items.length} limit={REPORT_PAGE_SIZE} busy={report.isFetching} onChange={setReportOffset} />
                <Group align="end"><NativeSelect label="Download format" value={downloadFormat} onChange={(event) => setDownloadFormat(event.currentTarget.value)} data={[{ value: 'csv', label: 'CSV' }, { value: 'json', label: 'JSON' }, { value: 'markdown', label: 'Markdown' }]} /><Button variant="default" leftSection={<IconDownload size={16} />} disabled={!report.data.items.length} loading={downloading} onClick={() => void downloadPage()}>Download current page</Button><Text size="xs" c="dimmed">Includes all evidence fields for these {report.data.items.length} rows.</Text></Group>
              </> : null}
              {downloadError ? <ErrorState error={downloadError} title="Download unavailable" /> : null}
            </Stack></Paper>}
          </Tabs.Panel>
          <Tabs.Panel value="relationships">
            <Checkbox mb="md" label="Browse connections for all nodes" checked={graphAll} onChange={(event) => { setGraphAll(event.currentTarget.checked); setGraphOffset(0); setRelationshipOffset(0); }} />
            {!selected && !graphAll ? <EmptyState title="Choose a node to inspect its connections." message="Connections describe routing, hosting, and management. Each finding retains its own observed target." /> : <Paper className="vb-card" p="lg"><Stack>
              <Title order={2} size="h4">Recorded connections</Title><Text size="sm" c="dimmed">Connections provide context. They do not transfer findings to connected hosts. Endpoints outside this page retain their IDs.</Text>
              {graph.isPending ? <LoadingState label="Loading connections." /> : graph.isError ? <ErrorState error={graph.error} /> : graph.data ? <>
                <div className="vb-table-wrap" tabIndex={0} role="region" aria-label="Connections table"><Table className="vb-table"><caption>Connections incident to {graphAll ? 'this page of nodes' : 'the selected node'}</caption><Table.Thead><Table.Tr>{['From', 'Connection', 'To', 'Source & time', 'Evidence'].map((label) => <Table.Th scope="col" key={label}>{label}</Table.Th>)}</Table.Tr></Table.Thead><Table.Tbody>{graph.data.relationships.map((edge) => <Table.Tr key={edge.id}><Table.Td>{edge.from_node_label ?? graphNodeName(edge.from_node_id)}</Table.Td><Table.Td>{relationLabels[edge.kind] ?? human(edge.kind)}</Table.Td><Table.Td>{edge.to_node_label ?? graphNodeName(edge.to_node_id)}</Table.Td><Table.Td><Text size="sm">{edge.source} · {edge.instance}</Text><Text size="xs" c="dimmed">Observed: {formatDate(edge.provenance?.observed_at)} · {human(edge.provenance?.time_meaning)}</Text></Table.Td><Table.Td><EvidenceDetails value={edge.evidence} /></Table.Td></Table.Tr>)}</Table.Tbody></Table></div>
                {!graph.data.relationships.length ? <Text size="sm">No connections recorded in this page.</Text> : null}
                <Paging name="relationships" offset={relationshipOffset} total={graph.data.relationship_total} count={graph.data.relationships.length} limit={NODE_PAGE_SIZE} busy={graph.isFetching} onChange={setRelationshipOffset} />
                {graphAll ? <><Text size="xs" c="dimmed">Node pages and connection pages are independent.</Text><Paging name="graph nodes" offset={graphOffset} total={graph.data.total} count={graph.data.nodes.length} limit={NODE_PAGE_SIZE} busy={graph.isFetching} onChange={(offset) => { setGraphOffset(offset); setRelationshipOffset(0); }} /></> : null}
              </> : null}
            </Stack></Paper>}
          </Tabs.Panel>
          <Tabs.Panel value="history"><Paper className="vb-card" p="lg"><Stack>
            <Title order={2} size="h4">Connection change history</Title><Text size="sm" c="dimmed">{selected ? 'Changes affecting the selected node.' : 'All recorded connection changes.'} Evidence and earlier states remain available.</Text>
            {history.isPending ? <LoadingState label="Loading change history." /> : history.isError ? <ErrorState error={history.error} /> : history.data ? <>
              {!history.data.items.length ? <Text>No connection changes recorded.</Text> : history.data.items.map((decision) => <Paper withBorder p="md" key={decision.id}><Stack gap="sm"><Group justify="space-between"><Text fw={600}>{human(decision.action)} · {formatDate(decision.occurred_at)}</Text>{administrator ? <Button size="xs" variant="default" disabled={!decision.undoable} onClick={() => { setUndoTarget(decision); setUndoReason(''); setUndoConfirmed(false); undoRequestKey.current = crypto.randomUUID(); undo.reset(); }}>Undo change {decision.decision_id}</Button> : null}</Group><Text size="sm">{decision.reason}</Text><Text size="xs" className="vb-mono">Change ID: {decision.decision_id}</Text>{decision.undo_block_reason ? <Text size="sm">Undo unavailable: {decision.undo_block_reason}</Text> : null}<EvidenceDetails value={decision.changes} /></Stack></Paper>)}
              <Paging name="changes" offset={historyOffset} total={history.data.total} count={history.data.items.length} limit={NODE_PAGE_SIZE} busy={history.isFetching} onChange={setHistoryOffset} />
            </> : null}
          </Stack></Paper></Tabs.Panel>
        </Stack>
      </div> : null}
      {administrator ? <Tabs.Panel value="import"><SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Paper className="vb-card" p="lg"><Stack>
          <Title order={2} size="h4">Import service connections</Title><Text size="sm" c="dimmed">Upload or paste a connections JSON object with source, instance, nodes, relationships, and attributions. Preview the exact changes before saving. Source identifiers and network scopes distinguish targets that share an address.</Text>
          <Text size="sm" c="dimmed">Source imports preserve newer dated evidence. For a reviewed correction to assignments or connections, set the JSON intent field to manual_correction; earlier facts remain in history.</Text>
          <FileInput label="Connections JSON file" description="JSON files up to 5 MB" accept="application/json,.json" onChange={(file) => void loadFile(file)} disabled={apply.isPending} clearable />
          <Textarea label="Connections JSON" value={draft} onChange={(event) => editDraft(event.currentTarget.value)} minRows={12} autosize maxRows={24} disabled={apply.isPending} styles={{ input: { fontFamily: 'monospace' } }} />
          {fileError ? <Alert color="red" role="alert">{fileError}</Alert> : null}
          {preview.isError ? <ErrorState error={preview.error} title="Connections could not be previewed" /> : null}
          <Button onClick={previewDraft} loading={preview.isPending} disabled={!draft.trim() || apply.isPending}>Preview connections</Button>
          {reviewedControls()}
          {apply.isError ? <ErrorState error={apply.error} title="Connections were not saved" /> : null}
        </Stack></Paper>
        <Paper className="vb-card" p="lg"><Stack>
          <Title order={2} size="h4">Find an existing host</Title><Text size="sm" c="dimmed">Choose the host explicitly, then use its asset ID in a node's asset_id field. Finding attribution still requires evidence; host selection does not assign findings.</Text>
          <form onSubmit={(event) => { event.preventDefault(); setAssetQuery(assetSearch.trim()); setAssetOffset(0); setAssetId(''); }}><Stack gap="sm"><TextInput label="Find hosts by name or ID" value={assetSearch} onChange={(event) => setAssetSearch(event.currentTarget.value)} /><Button variant="default" type="submit">Search existing hosts</Button></Stack></form>
          {assetQuery !== null ? assets.isPending ? <LoadingState label="Loading hosts." /> : assets.isError ? <ErrorState error={assets.error} /> : assets.data ? <>
            <NativeSelect label="Existing host" value={assetId} onChange={(event) => setAssetId(event.currentTarget.value)} data={[{ value: '', label: 'Choose a host explicitly' }, ...assets.data.items.map((asset) => ({ value: asset.id, label: `${asset.display_name ?? asset.canonical_hostname ?? 'Unnamed host'} (ID: ${asset.id})` }))]} />
            <Paging name="hosts" offset={assetOffset} total={assets.data.total} count={assets.data.items.length} limit={NODE_PAGE_SIZE} busy={assets.isFetching} onChange={(offset) => { setAssetOffset(offset); setAssetId(''); }} />
            {assetId ? <TextInput label="Selected host asset ID" value={assetId} readOnly /> : null}
          </> : null : null}
        </Stack></Paper>
      </SimpleGrid></Tabs.Panel> : null}
    </Tabs>
    <Modal opened={Boolean(mappingRow)} onClose={() => { if (!apply.isPending) { setMappingRow(null); invalidateReview(); } }} title="Review observation attribution" size="lg" closeOnClickOutside={!apply.isPending} closeOnEscape={!apply.isPending} withCloseButton={!apply.isPending}>
      {mappingRow ? <Stack>
        <Text fw={600}>{mappingRow.vulnerability_id ?? human(mappingRow.observation_kind)} · {mappingRow.source} / {mappingRow.instance}</Text>
        <Text size="sm">Current target: {mappingRow.node_label ?? 'Unassigned'}. {mappingRow.attribution_reason}</Text>
        <Text size="sm">Choose a target using evidence. A VIP connection or matching private IP alone does not prove which backend was assessed.</Text>
        <form onSubmit={(event) => { event.preventDefault(); setMappingQuery(mappingSearch.trim()); setMappingOffset(0); setMappingNodeId(''); invalidateReview(); }}><Group align="end"><TextInput label="Find attribution targets" value={mappingSearch} onChange={(event) => setMappingSearch(event.currentTarget.value)} disabled={apply.isPending} /><Button type="submit" variant="default" disabled={apply.isPending}>Search attribution targets</Button></Group></form>
        {mappingNodes.isPending ? <LoadingState label="Loading attribution targets." /> : mappingNodes.isError ? <ErrorState error={mappingNodes.error} /> : mappingNodes.data ? <>
          <NativeSelect label="Target for this observation" value={mappingNodeId} disabled={apply.isPending || mappingStatus === 'review_needed'} onChange={(event) => { setMappingNodeId(event.currentTarget.value); invalidateReview(); }} data={[{ value: '', label: 'Choose a target explicitly' }, ...mappingNodes.data.items.map((node) => ({ value: node.id, label: `${node.label} · ${kindLabels[node.kind] ?? human(node.kind)} · ${node.network_scope ?? 'Scope unknown'} · ${node.ip_address ?? node.dns_name ?? node.native_id} (ID: ${node.id})` }))]} />
          <Paging name="attribution targets" offset={mappingOffset} total={mappingNodes.data.total} count={mappingNodes.data.items.length} limit={NODE_PAGE_SIZE} busy={mappingNodes.isFetching || apply.isPending} onChange={(offset) => { setMappingOffset(offset); setMappingNodeId(''); invalidateReview(); }} />
        </> : null}
        <NativeSelect label="Attribution status" value={mappingStatus} disabled={apply.isPending} onChange={(event) => { setMappingStatus(event.currentTarget.value); if (event.currentTarget.value === 'review_needed') setMappingNodeId(''); invalidateReview(); }} data={[{ value: 'attributed', label: 'Attributed — evidence supports this target' }, { value: 'review_needed', label: 'Review needed — leave observation unassigned' }]} />
        {mappingStatus === 'review_needed' ? <Text size="sm">Review needed clears the target assignment while preserving the observation and its history.</Text> : null}
        <TextInput label="Reason for attribution" required value={reason} disabled={apply.isPending} onChange={(event) => { setReason(event.currentTarget.value); invalidateReview(); }} />
        <Button onClick={previewMapping} disabled={(mappingStatus === 'attributed' && !mappingNodeId) || !reason.trim() || apply.isPending} loading={preview.isPending}>Preview attribution</Button>
        {preview.isError ? <ErrorState error={preview.error} title="Attribution could not be previewed" /> : null}
        {reviewed ? <Text size="sm">Proposed target: {mappingStatus === 'review_needed' ? 'Unassigned' : mappingNodes.data?.items.find((node) => node.id === mappingNodeId)?.label ?? mappingNodeId} · {human(mappingStatus)}. {reason}</Text> : null}
        {reviewedControls(true)}
        {apply.isError ? <ErrorState error={apply.error} title="Attribution was not saved" /> : null}
      </Stack> : null}
    </Modal>
    <Modal opened={factHistoryOpen} onClose={() => setFactHistoryOpen(false)} title={`Fact history: ${selected?.label ?? 'Selected target'}`} size="lg">
      {factHistory.isPending ? <LoadingState label="Loading fact history." /> : factHistory.isError ? <ErrorState error={factHistory.error} /> : factHistory.data ? <Stack>
        <Text size="sm">Earlier and conflicting observations are retained with their source times. An older import can describe an earlier state.</Text>
        {factHistory.data.facts.length ? factHistory.data.facts.map((fact) => <Paper key={fact.id} withBorder p="md"><Stack gap="xs"><Text size="sm" fw={600}>{fact.provenance.source ?? 'Source unknown'} · {fact.provenance.instance ?? 'Instance unknown'}</Text><Text size="xs">Observed: {formatDate(fact.observed_at)} · Imported: {formatDate(fact.imported_at)} · {human(fact.provenance.time_meaning)}</Text>{fact.payload && typeof fact.payload === 'object' && 'facts' in fact.payload && fact.payload.facts && typeof fact.payload.facts === 'object' ? <FactValues facts={fact.payload.facts as Record<string, unknown>} /> : null}<EvidenceDetails value={fact.payload} /></Stack></Paper>) : <Text>No fact history recorded.</Text>}
        <Paging name="fact observations" offset={factOffset} total={factHistory.data.fact_total} count={factHistory.data.facts.length} limit={NODE_PAGE_SIZE} busy={factHistory.isFetching} onChange={setFactOffset} />
      </Stack> : null}
    </Modal>
    <Modal opened={Boolean(undoTarget)} onClose={() => { if (!undo.isPending) setUndoTarget(null); }} title="Review undo of connection change" closeOnClickOutside={!undo.isPending} closeOnEscape={!undo.isPending} withCloseButton={!undo.isPending}>
      {undoTarget ? <Stack><Text size="sm">Undo change {undoTarget.decision_id}: {undoTarget.reason}</Text><Text size="sm">This restores its earlier connections only if their recorded versions still match. Later changes can block the undo.</Text><EvidenceDetails value={undoTarget.changes} /><TextInput label="Reason for undo" required value={undoReason} onChange={(event) => setUndoReason(event.currentTarget.value)} disabled={undo.isPending} /><Checkbox label="I reviewed this change and want to undo it." checked={undoConfirmed} onChange={(event) => setUndoConfirmed(event.currentTarget.checked)} disabled={undo.isPending} />{undo.isError ? <ErrorState error={undo.error} title="Change could not be undone" /> : null}<Button disabled={!undoConfirmed || !undoReason.trim()} loading={undo.isPending} onClick={() => undo.mutate()}>Confirm undo</Button></Stack> : null}
    </Modal>
  </>;
}
