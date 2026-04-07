# Relatório: O que está feito e o que fazer

**Data:** Abril 2026
**Versão atual:** 0.6.0 (8 releases em 15 dias)

---

## PARTE 1: O QUE ESTÁ FEITO

### Core Engine — 100% completo

| Componente | Status | Detalhes |
|-----------|--------|----------|
| L1 Regex | Completo | 40+ regras EN + 20 multilingual (DE/ES/FR/PT), context modifiers |
| L2 Classifier | Completo | DeBERTa-v3-xsmall ONNX (22M params), auto-download HuggingFace |
| L3 Similarity | Completo | Contrastive MiniLM ONNX INT8 (113MB) + FAISS IVF, 25,160 attacks |
| L4 Structural | Completo | Boundary detection, Cialdini, Shannon entropy, delimiter injection |
| L5 Negative Selection | Completo | IsolationForest, 11 features, <1ms, auto-download HuggingFace |
| Meta-classifier | Completo | LogisticRegression, 10 features, F1=93.5% (autoexperiment-tuned) |
| Inflammation cascade | Completo | Session-level, exponential decay (×0.7), thread-safe |
| Text normalization | Completo | NFKC, zero-width chars, sliding window segmentation |

### Métricas atuais

| Métrica | Valor |
|---------|-------|
| F1 Score | **93.53%** |
| Recall | 98.15% (3 FN em 162 ataques) |
| Precision | 89.33% (19 FP em 353 benign) |
| Avg Latency | ~27ms |
| P95 Latency | ~209ms |
| Adversarial Recall | 94.4% (46 evasion prompts) |
| Attack DB | 25,160 entradas, 10 fontes |
| Install size | ~50MB (sem PyTorch) |
| Cold start | ~1s |

### Interfaces — 100% completo

| Interface | Status | Detalhes |
|----------|--------|----------|
| Python SDK | Completo | `from prompt_armor import analyze` — lazy init, thread-safe |
| CLI | Completo | `analyze`, `scan`, `config` — exit codes semânticos (0/1/2/3) |
| MCP Server | Completo | `prompt-armor-mcp` — FastMCP, Claude Desktop/Cursor ready |
| Docker | Completo | `python:3.12-slim`, pre-downloads todos os modelos |

### Council Mode — 80% completo

| Componente | Status | Detalhes |
|-----------|--------|----------|
| Provider abstraction | Completo | BaseProvider ABC, extensível |
| OllamaProvider | Completo | phi3:mini, anti-injection hardened |
| Veto logic | Completo | MALICIOUS+HIGH→BLOCK, SAFE+HIGH→ALLOW |
| OpenRouter provider | Pendente | Abstração pronta, implementação faltando |
| Budget enforcement | Pendente | Campo existe no config, lógica não implementada |

### Dashboard — 70% completo

| Componente | Status | Detalhes |
|-----------|--------|----------|
| Overview page | Completo | Stats, threat timeline, council stats |
| Live feed | Completo | Real-time, refresh configurável, council indicators |
| Timeline | Completo | Agrupado por decisão, trends |
| Analysis detail | Completo | Layer breakdown, council verdict, evidence |
| Tema CRT | Completo | Terminal green-on-black, neon glow |
| Timezone local | Completo | Conversão automática |
| Auth/multi-tenant | Ausente | Dashboard é local-only |
| Admin console | Ausente | Sem UI para config |
| Cloud deploy | Ausente | Só roda localhost |

### Testes — 95% completo

| Suite | Arquivos | Cobertura |
|-------|----------|-----------|
| Unit tests | 11 arquivos | Engine, fusion, 5 layers, council, collector, config, models |
| Integration tests | 2 arquivos | CLI, MCP server |
| Benchmark | 515 samples | 353 benign + 162 malicious |
| Adversarial | 46 prompts | 8 categorias de evasão |
| CI/CD | 3 workflows | Lint + test (3 Python versions) + publish |

### Documentação — 85% completo

| Doc | Status |
|-----|--------|
| README.md | Completo (comparison table, examples, architecture) |
| Quickstart | Completo |
| Configuration | Completo |
| Layers deep-dive | Completo |
| CLI reference | Completo |
| MCP guide | Completo |
| Benchmark | Completo |
| Blog post | 1 artigo |
| CHANGELOG | Completo (8 releases) |
| CONTRIBUTING | Completo |
| SECURITY.md | Completo |
| API reference (docstrings) | Parcial |

### Scripts/Tooling — 100% completo

| Script | Propósito |
|--------|-----------|
| `train_fusion.py` | Treinar meta-classifier |
| `dump_layer_scores.py` | Extrair scores por layer |
| `train_l3_contrastive.py` | Fine-tune embeddings |
| `export_l3_onnx.py` | Export L3 → ONNX INT8 |
| `train_l5_model.py` | Treinar IsolationForest |
| `build_attack_db.py` | Construir DB de ataques (25K) |
| `build_benchmark.py` | Construir dataset benchmark |
| `expand_benchmark.py` | Expandir com adversarial/multilingual |
| `export_l2_model.py` | Export L2 → ONNX |
| `autoexperiment.py` | Otimização autônoma de parâmetros |

### Distribuição — 90% completo

| Canal | Status |
|-------|--------|
| PyPI | Publicado (`pip install prompt-armor`) |
| GitHub | 8 releases (v0.1.0→v0.6.0) |
| HuggingFace | 3 modelos (L2, L3, L3-training) |
| Docker | Dockerfile funcional |
| Docker Hub | Não publicado |
| Homebrew | Não disponível |

---

## PARTE 2: O QUE FAZER

Organizado por prioridade para o modelo open-core.

### Prioridade 1: Go-to-Market (Próximos 30 dias)

**Objetivo: 1K stars + 10K downloads**

| # | Ação | Esforço | Impacto |
|---|------|---------|---------|
| 1.1 | **Show HN post** — escrever post otimizado, timing (terça/quarta 8am PT) | 2h | Muito alto |
| 1.2 | **Post LinkedIn** — aproveitar 60K followers, demo visual | 1h | Alto |
| 1.3 | **awesome-lists** — PR para awesome-llm-security, awesome-mcp-servers, awesome-ai-safety | 1h | Médio |
| 1.4 | **Docker Hub** — publicar imagem oficial `prompt-armor/prompt-armor` | 1h | Médio |
| 1.5 | **Blog post técnico** — "How we detect prompt injection in 27ms without an LLM" | 4h | Alto |
| 1.6 | **Benchmark público vs concorrentes** — rodar LLM Guard, Lakera no mesmo dataset | 8h | Muito alto |
| 1.7 | **Demo GIF/video** — terminal recording mostrando CLI + dashboard | 2h | Alto |

### Prioridade 2: Melhorias Técnicas para v0.7 (30-60 dias)

**Objetivo: F1 > 94%, FPR < 5%, adversarial recall > 97%**

| # | Ação | Esforço | Impacto |
|---|------|---------|---------|
| 2.1 | **Expandir benchmark para 2000+ samples** — mais hard negatives, mais adversarial | 4h | Alto |
| 2.2 | **Fix 2 adversarial evasions** — conversational probes (L5 0.50-0.62) | 4h | Médio |
| 2.3 | **Fix FP "ignore previous errors"** — code review contexts | 2h | Médio |
| 2.4 | **Retrain meta-classifier** com benchmark expandido | 2h | Alto |
| 2.5 | **OpenRouter provider** para Council — multi-judge (Claude Haiku, GPT-4o-mini) | 6h | Médio |
| 2.6 | **REST API server** — FastAPI wrapper para quem não quer CLI/MCP | 4h | Alto |
| 2.7 | **Streaming/webhook mode** — análise em tempo real de conversas | 8h | Médio |
| 2.8 | **Rate limiting + caching** — para uso em produção | 4h | Médio |

### Prioridade 3: Fundação para Monetização (60-90 dias)

**Objetivo: Infraestrutura para features paid**

| # | Ação | Esforço | Impacto |
|---|------|---------|---------|
| 3.1 | **Dashboard Cloud** — deploy do dashboard em Vercel + Supabase (auth, multi-tenant) | 20h | Muito alto |
| 3.2 | **Threat Intel Feed** — pipeline automatizado de novos ataques (scrape CTF, forums, papers) | 16h | Muito alto |
| 3.3 | **API managed** — endpoint cloud com API keys, rate limits, billing (Stripe) | 20h | Muito alto |
| 3.4 | **Modelos premium** — L2/L3 maiores (DeBERTa-base, MiniLM-L6 → L12), fine-tuned em dados enterprise | 16h | Alto |
| 3.5 | **Auto-update de modelos** — pipeline CI que retreina e publica no HuggingFace periodicamente | 8h | Médio |
| 3.6 | **Compliance reports** — export PDF com métricas, decisões, evidence (EU AI Act ready) | 8h | Alto |
| 3.7 | **Waitlist/landing page** — coletar emails para cloud launch | 4h | Alto |

### Prioridade 4: Enterprise Features (90-180 dias)

**Objetivo: Primeiros $10K MRR**

| # | Ação | Esforço | Impacto |
|---|------|---------|---------|
| 4.1 | **Multi-tenant dashboard** — organizations, teams, RBAC | 40h | Muito alto |
| 4.2 | **SSO (SAML/OIDC)** — requisito enterprise | 16h | Alto |
| 4.3 | **Custom rules UI** — editor visual de regex rules no dashboard | 12h | Médio |
| 4.4 | **Alertas** — Slack/email/webhook quando threshold é atingido | 8h | Alto |
| 4.5 | **Red teaming automatizado** — adversarial testing contínuo (evolução do autoexperiment) | 20h | Muito alto |
| 4.6 | **SDK multi-linguagem** — TypeScript/Go wrappers chamando CLI ou API | 12h | Médio |
| 4.7 | **AWS/GCP Marketplace** — listing para enterprise discovery | 8h | Alto |
| 4.8 | **SOC 2 Type II** — processo de compliance | 80h+ | Alto (gate para enterprise US) |

### Prioridade 5: Escala e Diferenciação (6-12 meses)

| # | Ação | Esforço | Impacto |
|---|------|---------|---------|
| 5.1 | **Agentic AI protection** — análise de tool calls, multi-turn sessions | 40h | Muito alto |
| 5.2 | **Multi-modal** — detectar injection em imagens (OCR + análise) | 30h | Alto |
| 5.3 | **Fine-tune contínuo** — L2/L3 retreinam com dados de produção (com consent) | 20h | Alto |
| 5.4 | **Threat intelligence sharing** — feed de ataques entre clientes (anonimizado) | 20h | Muito alto |
| 5.5 | **Partnership program** — integrações oficiais LangChain, LlamaIndex, CrewAI | 16h | Alto |
| 5.6 | **LATAM go-to-market** — suporte PT/ES, compliance LGPD, contatos locais | 20h | Alto |

---

## PARTE 3: GAPS CRÍTICOS

Coisas que faltam e que bloqueiam monetização se não forem feitas.

### Gap 1: Sem API REST

O SDK Python e CLI existem, mas muitos usuários (especialmente enterprise) querem um endpoint HTTP. Sem isso, a integração é limitada a Python-native ou MCP.

**Solução**: FastAPI server com `/analyze` endpoint, API keys, rate limiting. Esforço: 4h para MVP.

### Gap 2: Dashboard é local-only

O dashboard existe e é funcional, mas roda em localhost com SQLite. Não serve para teams, não tem auth, não persiste entre máquinas.

**Solução**: Deploy Vercel + Supabase (Postgres). Auth via Clerk/Supabase Auth. Esforço: 20h.

### Gap 3: Sem landing page / waitlist

Não existe um site marketing ou forma de capturar leads interessados.

**Solução**: Landing page simples (Vercel) com email capture. Esforço: 4h.

### Gap 4: Sem benchmark comparativo público

O README tem uma tabela de comparação, mas sem dados verificáveis. Um benchmark público rodando prompt-armor vs LLM Guard vs Lakera no mesmo dataset seria o argumento definitivo.

**Solução**: Script que roda os concorrentes no mesmo dataset, publica resultados. Esforço: 8h.

### Gap 5: Sem telemetria opt-in

Sem dados de uso, é impossível saber quantas pessoas usam, quais layers são mais úteis, qual a taxa real de FP em produção.

**Solução**: Telemetria opt-in (à la Next.js) — contagem anônima de análises, layers ativos, decisões. Esforço: 4h.

---

## PARTE 4: QUICK WINS

Coisas que podem ser feitas em <4h cada e têm impacto desproporcional.

| # | Quick Win | Esforço | Por quê |
|---|-----------|---------|---------|
| QW1 | Publicar no Docker Hub | 1h | Zero-friction para testar |
| QW2 | GitHub Topics + social preview | 30min | SEO + discovery |
| QW3 | Badge de stars/downloads no README | 15min | Social proof |
| QW4 | `prompt-armor --benchmark` CLI flag | 2h | Self-service benchmark |
| QW5 | Example notebooks (Colab) | 3h | Reduz barreira de entrada |
| QW6 | Pre-commit hook integration | 1h | Developers adoram |
| QW7 | GitHub Sponsors setup | 30min | Revenue stream passivo |

---

## PARTE 5: TIMELINE SUGERIDA

```
Semana 1-2: Go-to-Market (P1)
├── Show HN + LinkedIn post
├── Docker Hub publish
├── awesome-lists PRs
└── Demo GIF

Semana 3-4: Quick Wins + v0.7 prep
├── QW1-QW7
├── Expandir benchmark (2.1)
├── Fix adversarial evasions (2.2, 2.3)
└── REST API server (2.6)

Mês 2: v0.7 Release
├── Retrain meta-classifier (2.4)
├── OpenRouter provider (2.5)
├── Benchmark comparativo público (1.6)
└── Blog post técnico (1.5)

Mês 3: Cloud Foundation (P3)
├── Landing page + waitlist (3.7)
├── Dashboard Cloud MVP (3.1)
├── API managed MVP (3.3)
└── Threat Intel Feed v1 (3.2)

Mês 4-6: Monetização (P3/P4)
├── Compliance reports (3.6)
├── Alertas (4.4)
├── Red teaming automatizado (4.5)
└── Primeiros clientes LATAM
```

---

## PARTE 6: MÉTRICAS DE ACOMPANHAMENTO

| Fase | Métrica | Target |
|------|---------|--------|
| Go-to-Market | GitHub stars | 1K em 60 dias |
| Go-to-Market | PyPI downloads/mês | 10K em 60 dias |
| Go-to-Market | Docker pulls | 1K em 60 dias |
| Técnico | F1 Score | >94% (v0.7) |
| Técnico | Adversarial Recall | >97% (v0.7) |
| Técnico | FPR | <5% (v0.7) |
| Cloud | Waitlist signups | 500 em 90 dias |
| Revenue | MRR | $5K em 6 meses |
| Revenue | Paying customers | 10 em 6 meses |
| Community | Contributors | 5 em 90 dias |
