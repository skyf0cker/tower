export function TowerLogo({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none">
      <path d="M8 2L13 13H10.6L8 7.2L5.4 13H3L8 2Z" fill="#FFFFFF" />
      <circle cx="8" cy="4.2" r="1.4" fill="var(--color-primary)" />
    </svg>
  );
}

export function GridIcon({ active }: { active?: boolean }) {
  const stroke = active ? "var(--color-primary)" : "var(--color-muted)";
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <rect x="2" y="2" width="5" height="5" rx="1" stroke={stroke} strokeWidth="1.5" />
      <rect x="9" y="2" width="5" height="5" rx="1" stroke={stroke} strokeWidth="1.5" />
      <rect x="2" y="9" width="5" height="5" rx="1" stroke={stroke} strokeWidth="1.5" />
      <rect x="9" y="9" width="5" height="5" rx="1" stroke={stroke} strokeWidth="1.5" />
    </svg>
  );
}

export function StackIcon({ active }: { active?: boolean }) {
  const stroke = active ? "var(--color-primary)" : "var(--color-muted)";
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M2.5 5.5L8 2.5L13.5 5.5L8 8.5L2.5 5.5Z" stroke={stroke} strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M2.5 10L8 13L13.5 10" stroke={stroke} strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function GlobeIcon({ active }: { active?: boolean }) {
  const stroke = active ? "var(--color-primary)" : "var(--color-muted)";
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="5.5" stroke={stroke} strokeWidth="1.4" />
      <path d="M2.8 8H13.2M8 2.8C9.6 4.4 9.6 11.6 8 13.2" stroke={stroke} strokeWidth="1.3" />
    </svg>
  );
}

export function RulesIcon({ active }: { active?: boolean }) {
  const stroke = active ? "var(--color-primary)" : "var(--color-muted)";
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M3 4H13M3 8H10M3 12H7" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="12" cy="11.5" r="2" stroke={stroke} strokeWidth="1.4" />
    </svg>
  );
}

export function PulseIcon({ active }: { active?: boolean }) {
  const stroke = active ? "var(--color-primary)" : "var(--color-muted)";
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M2.5 9.5H5L6.8 5L9.2 11.5L11 8H13.5" stroke={stroke} strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function CopyIcon({ color = "#FFFFFF" }: { color?: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <rect x="4.5" y="4.5" width="7" height="7" rx="1.4" stroke={color} strokeWidth="1.4" />
      <path d="M2.5 9.5V3.5C2.5 2.95 2.95 2.5 3.5 2.5H9.5" stroke={color} strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

export function SearchIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none">
      <circle cx="6" cy="6" r="4.3" stroke="var(--color-subtle)" strokeWidth="1.4" />
      <path d="M9.5 9.5L12.5 12.5" stroke="var(--color-subtle)" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

export function SunIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="3.1" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M8 1.8V3.2M8 12.8V14.2M1.8 8H3.2M12.8 8H14.2M3.6 3.6L4.6 4.6M11.4 11.4L12.4 12.4M12.4 3.6L11.4 4.6M4.6 11.4L3.6 12.4"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function MoonIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
      <path
        d="M13.2 9.8A5.4 5.4 0 0 1 6.2 2.8a5.4 5.4 0 1 0 7 7Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function MonitorIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
      <rect x="2.2" y="3" width="11.6" height="7.8" rx="1.4" stroke="currentColor" strokeWidth="1.4" />
      <path d="M5.5 13.2H10.5M8 10.8V13.2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

export function formatRelativeTime(timestamp: number | null): string {
  if (!timestamp) return "未同步";
  const diffSec = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (diffSec < 60) return "刚刚";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.floor(diffHr / 24)}d ago`;
}
