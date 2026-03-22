import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Convert a DB timestamp (UTC or naive) to user's local timezone.
 * SQLite stores "2026-03-21 14:30:00" — we treat it as UTC and
 * format in the browser's local timezone.
 */
export function formatLocalTime(dbTimestamp: string): string {
  const date = new Date(dbTimestamp + "Z"); // append Z to parse as UTC
  if (isNaN(date.getTime())) return dbTimestamp;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function formatLocalDateTime(dbTimestamp: string): string {
  const date = new Date(dbTimestamp + "Z");
  if (isNaN(date.getTime())) return dbTimestamp;
  return date.toLocaleString([], {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
}
