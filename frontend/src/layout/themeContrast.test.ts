import { describe, expect, it } from 'vitest';
import styles from '../styles.css?raw';

function luminance(hex: string) {
  const linear = hex.replace('#', '').match(/../g)!.map((part) => {
    const channel = parseInt(part, 16) / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}
function ratio(first: string, second: string) {
  const values = [luminance(first), luminance(second)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}
const tokenBlocks = [...styles.matchAll(/:root(?:\[data-mantine-color-scheme='dark'\])?\s*\{([^}]+)\}/g)].map((match) => Object.fromEntries([...match[1].matchAll(/--vb-([\w-]+):\s*(#[\da-f]{6})/g)].map((token) => [token[1], token[2]])));

describe('theme color tokens (limited contrast check)', () => {
  it.each(['light', 'dark'])('keeps %s body text and muted text above 4.5:1 and focus above 3:1', (mode) => {
    const tokens = tokenBlocks[mode === 'light' ? 0 : 1];
    for (const background of ['page-bg', 'surface', 'subtle']) {
      for (const foreground of ['text', 'muted']) expect(ratio(tokens[foreground], tokens[background])).toBeGreaterThanOrEqual(4.5);
      expect(ratio(tokens.focus, tokens[background])).toBeGreaterThanOrEqual(3);
    }
  });
  it('keeps navigation text readable on normal and selected backgrounds', () => {
    expect(ratio('#d7d9e5', '#1c1d28')).toBeGreaterThanOrEqual(4.5);
    expect(ratio('#b7b9ca', '#1c1d28')).toBeGreaterThanOrEqual(4.5);
    expect(ratio('#ffffff', '#494186')).toBeGreaterThanOrEqual(4.5);
  });
});
