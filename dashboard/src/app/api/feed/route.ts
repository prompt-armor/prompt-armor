import { getRecentAnalyses } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const decision = searchParams.get("decision") || "all";
  const limit = parseInt(searchParams.get("limit") || "100", 10);

  try {
    const analyses = getRecentAnalyses(limit, decision);
    return NextResponse.json(analyses);
  } catch (error) {
    return NextResponse.json([], { status: 200 });
  }
}
