import { getAnalysisById } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const id = parseInt(searchParams.get("id") || "0", 10);

  if (!id) {
    return NextResponse.json({ error: "Missing id parameter" }, { status: 400 });
  }

  try {
    const analysis = getAnalysisById(id);
    if (!analysis) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }
    return NextResponse.json(analysis);
  } catch {
    return NextResponse.json({ error: "Database error" }, { status: 500 });
  }
}
