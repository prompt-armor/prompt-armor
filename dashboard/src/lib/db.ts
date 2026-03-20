import Database from "better-sqlite3";
import path from "path";
import os from "os";

const DB_PATH =
  process.env.PROMPT_ARMOR_DB ||
  path.join(os.homedir(), ".prompt-armor", "analytics.db");

let db: Database.Database | null = null;

function getDb(): Database.Database {
  if (!db) {
    try {
      db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
      db.pragma("journal_mode = WAL");
    } catch {
      throw new Error(
        `Analytics database not found at ${DB_PATH}. Enable analytics in .prompt-armor.yml first.`
      );
    }
  }
  return db;
}

export interface Analysis {
  id: number;
  timestamp: string;
  prompt_hash: string;
  prompt_text: string | null;
  prompt_length: number;
  risk_score: number;
  confidence: number;
  decision: string;
  categories: string;
  evidence: string;
  layer_scores: string;
  latency_ms: number;
  needs_council: number;
}

export interface OverviewStats {
  total: number;
  allow: number;
  warn: number;
  block: number;
  avgLatency: number;
  avgScore: number;
  today: number;
  blocksLastHour: number;
}

export interface CategoryCount {
  category: string;
  count: number;
}

export interface TimelinePoint {
  hour: string;
  allow: number;
  warn: number;
  block: number;
}

export function getOverviewStats(): OverviewStats {
  const d = getDb();
  const row = d.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN decision='allow' THEN 1 ELSE 0 END) as allow,
      SUM(CASE WHEN decision='warn' THEN 1 ELSE 0 END) as warn,
      SUM(CASE WHEN decision='block' THEN 1 ELSE 0 END) as block,
      AVG(latency_ms) as avgLatency,
      AVG(risk_score) as avgScore,
      SUM(CASE WHEN timestamp >= datetime('now', '-1 day') THEN 1 ELSE 0 END) as today,
      SUM(CASE WHEN decision='block' AND timestamp >= datetime('now', '-1 hours') THEN 1 ELSE 0 END) as blocksLastHour
    FROM analyses
  `).get() as {
    total: number; allow: number; warn: number; block: number;
    avgLatency: number | null; avgScore: number | null; today: number; blocksLastHour: number;
  };

  return {
    total: row.total,
    allow: row.allow,
    warn: row.warn,
    block: row.block,
    avgLatency: row.avgLatency ?? 0,
    avgScore: row.avgScore ?? 0,
    today: row.today,
    blocksLastHour: row.blocksLastHour,
  };
}

export function getTopCategories(limit = 8): CategoryCount[] {
  const d = getDb();
  const rows = d.prepare("SELECT categories FROM analyses WHERE decision != 'allow'").all() as { categories: string }[];

  const counts: Record<string, number> = {};
  for (const row of rows) {
    try {
      const cats = JSON.parse(row.categories) as string[];
      for (const cat of cats) {
        counts[cat] = (counts[cat] || 0) + 1;
      }
    } catch { /* skip malformed */ }
  }

  return Object.entries(counts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, limit)
    .map(([category, count]) => ({ category, count }));
}

export function getRecentAnalyses(limit = 50, decision?: string): Analysis[] {
  const d = getDb();
  if (decision && decision !== "all") {
    return d
      .prepare("SELECT * FROM analyses WHERE decision = ? ORDER BY id DESC LIMIT ?")
      .all(decision, limit) as Analysis[];
  }
  return d
    .prepare("SELECT * FROM analyses ORDER BY id DESC LIMIT ?")
    .all(limit) as Analysis[];
}

export function getAnalysisById(id: number): Analysis | undefined {
  const d = getDb();
  return d.prepare("SELECT * FROM analyses WHERE id = ?").get(id) as Analysis | undefined;
}

export function getTimeline(hours = 24): TimelinePoint[] {
  const d = getDb();
  const rows = d
    .prepare(`
      SELECT
        strftime('%Y-%m-%d %H:00', timestamp) as hour,
        SUM(CASE WHEN decision='allow' THEN 1 ELSE 0 END) as allow,
        SUM(CASE WHEN decision='warn' THEN 1 ELSE 0 END) as warn,
        SUM(CASE WHEN decision='block' THEN 1 ELSE 0 END) as block
      FROM analyses
      WHERE timestamp >= datetime('now', '-' || ? || ' hours')
      GROUP BY hour
      ORDER BY hour
    `)
    .all(hours) as TimelinePoint[];
  return rows;
}
