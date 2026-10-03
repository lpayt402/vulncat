export function formatDate(value?: string | null, withTime = false) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    ...(withTime ? { timeStyle: 'short' as const } : {}),
  }).format(date);
}

export function formatNumber(value?: number | null) {
  return Number(value ?? 0).toLocaleString();
}

export function humanize(value?: string | null) {
  if (!value) return '—';
  return value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function getTagNames(tags?: Array<string | { name: string }>) {
  return (tags ?? []).map((tag) => (typeof tag === 'string' ? tag : tag.name));
}
