# Relatório: Comercialização vs Open-Source do prompt-armor

**Data:** Abril 2026
**Autor:** Análise estratégica para prompt-armor

---

## 1. Contexto do Mercado

### Tamanho e crescimento

| Segmento | 2024 | 2025 | Projeção 2033-34 | CAGR |
|----------|------|------|------------------|------|
| LLM Security Platforms | $2.37B | — | — | 21.4% |
| AI Prompt Security (nicho) | $1.51B | $1.98B | $5.87B (2029) | 31.5% |
| LLMs in Cybersecurity (amplo) | $3.6B | $5.66B | $250B | 52.8% |

**Drivers principais:**
- EU AI Act entra em vigor em agosto de 2026 (multas de até 7% da receita global)
- 83% das empresas planejam agentic AI, mas só 29% se sentem seguras
- Prompt injection é a vulnerabilidade #1 em 73% dos deploys de AI em produção
- Taxa de sucesso de ataques: 84% em sistemas agentic

### Consolidação acelerada (2024-2026)

| Alvo | Comprador | Valor | Data |
|------|-----------|-------|------|
| Robust Intelligence | Cisco | Não divulgado | 2024 |
| Protect AI (LLM Guard) | Palo Alto Networks | $500M | Jul 2025 |
| CalypsoAI | F5 | Não divulgado | Set 2025 |

O mercado está em consolidação ativa. Grandes vendors de segurança (Palo Alto, Cisco, F5) estão adquirindo startups especializadas a valores expressivos.

---

## 2. Mapa Competitivo

| | prompt-armor | Lakera Guard | LLM Guard | Prompt Security | Arthur AI |
|--|-------------|-------------|-----------|-----------------|-----------|
| **Modelo** | Open-source | Free + Enterprise | Open-source + Enterprise | SaaS | Freemium + Enterprise |
| **Preço** | Grátis | Free (10K req/mês) + custom | Grátis + custom | $50-120/mês + enterprise | $0/$60/mês + custom |
| **Offline** | Sim | Não | Sim | Não | Parcial |
| **Precisa de LLM** | Não | Não | Não | Não | Parcial |
| **Latência** | ~27ms | ~50ms | 200-500ms | N/A | N/A |
| **Camadas** | 5 (fusão treinada) | ? (proprietário) | 1 por scanner | ? | N/A |
| **MCP** | Sim | Não | Não | Não | Não |
| **Licença** | Apache 2.0 | Proprietário | MIT | Proprietário | Parcial OSS |
| **Status** | Indie/ativo | Check Point | Palo Alto ($500M) | $18M funding | Independente |

### Diferenciais únicos do prompt-armor

1. **Único com 5 camadas fundidas por meta-classifier treinado** — concorrentes usam scanners independentes
2. **Único com MCP Server nativo** — integração direta com Claude Desktop, Cursor, etc.
3. **Mais rápido** (~27ms vs 50-500ms dos concorrentes)
4. **100% offline** — zero dependência de API, zero custo por request
5. **Apache 2.0** — mais permissivo que concorrentes proprietários
6. **CI/CD native** — exit codes semânticos, nenhum concorrente tem

---

## 3. Modelos de Negócio Possíveis

### Opção A: Open-Core (Recomendado)

**Inspiração:** CrewAI, Elastic, Snyk

| Camada | O que inclui | Preço |
|--------|-------------|-------|
| **Community (OSS)** | Lite Engine (5 layers), CLI, MCP Server, SDK | Grátis (Apache 2.0) |
| **Pro (Self-hosted)** | Council mode multi-judge, dashboard analytics, threat intel feed, modelos atualizados continuamente | $99-299/mês |
| **Cloud (Managed)** | API managed, dashboard cloud, auto-updates, SLA, compliance reports, SSO | $499-2000/mês |
| **Enterprise** | On-prem, custom models, red teaming, SLA customizado, support dedicado | Custom ($5K-20K/mês) |

**Vantagens:**
- Adoção grassroots via open-source (o caminho do Snyk: $343M ARR)
- Lock-in natural: quem usa o OSS, precisa de mais quando escala
- Community contribui com regras, attack samples, integrações
- Credibilidade técnica (auditável, reproduzível)

**Riscos:**
- AWS/cloud providers podem hospedar sem contribuir (o problema do Elastic)
- Precisa de velocidade — janela de oportunidade fecha com consolidação
- Revenue demora: Snyk levou 2 anos do OSS ao primeiro $1M ARR

### Opção B: SaaS Puro

**Inspiração:** Prompt Security, Lakera

| Tier | Inclui | Preço |
|------|--------|-------|
| **Free** | 10K requests/mês, 5 layers, dashboard básico | Grátis |
| **Team** | 100K requests/mês, council mode, analytics | $120/mês |
| **Business** | 1M requests/mês, custom rules, API priority | $500/mês |
| **Enterprise** | Unlimited, on-prem option, compliance, SLA | Custom |

**Vantagens:**
- Revenue mais rápido (pay-per-use desde dia 1)
- Controle total sobre pricing e features
- Dados de telemetria para melhorar modelos

**Riscos:**
- Compete com open-source (LLM Guard tem 2.5M downloads)
- Sem community = sem contribuições = tem que fazer tudo sozinho
- Harder to build trust em security sem código auditável
- Latência de API add overhead vs solução local

### Opção C: Acquisition Target

**Inspiração:** Protect AI ($500M), Robust Intelligence (Cisco), CalypsoAI (F5)

- Construir o melhor open-source do segmento
- Gerar adoção significativa (>500K downloads, >5K GitHub stars)
- Ser adquirido por Palo Alto, CrowdStrike, Cloudflare, Datadog, etc.

**Vantagens:**
- Exit mais rápido (Protect AI: fundação → $500M em ~3 anos)
- Não precisa resolver go-to-market enterprise
- Foco 100% em tech + community

**Riscos:**
- Sem receita = sem leverage na negociação
- Timing dependente do mercado de M&A
- Pode não acontecer

---

## 4. Análise: O que Monetizar

### O que fica open-source (e por quê)

| Componente | Razão |
|-----------|-------|
| Lite Engine (5 layers) | É o hook de adoção. Quanto mais gente usa, mais valioso o ecossistema |
| CLI + exit codes | Desenvolvedores instalam no CI primeiro, depois pedem features pro |
| MCP Server | Diferencial competitivo, mas precisa ser grátis para viralizar |
| SDK (analyze()) | API pública = integrações de terceiros = efeito de rede |
| Regras regex (L1) | Community pode contribuir, mais olhos = melhores regras |

### O que monetizar (e por quê)

| Componente | Razão | Valor |
|-----------|-------|-------|
| **Council Mode managed** | Requer infra (ollama/OpenRouter), billing, rate limiting | Alto |
| **Dashboard cloud** | Analytics, trends, alertas, export — precisa de backend | Alto |
| **Threat intel feed** | Attack DB atualizado continuamente, zero-day alerts | Muito alto |
| **Modelos premium** | L2/L3 maiores, fine-tuned em dados proprietários | Alto |
| **Auto-update de modelos** | Retraining automatizado com novos dados | Médio |
| **Compliance reports** | EU AI Act, SOC 2, HIPAA — enterprises pagam | Alto |
| **Red teaming automatizado** | Adversarial testing contínuo (autoresearch-style) | Muito alto |
| **Multi-tenant management** | Gestão de múltiplos projetos/teams | Médio |

---

## 5. Pricing Benchmark

### Per-request (mercado)

| Vendor | Free Tier | Paid |
|--------|-----------|------|
| Lakera | 10K req/mês | Custom |
| Prompt Security | — | $0.12/1K requests |
| Arthur AI | Free tier | $60/mês |
| prompt-armor (proposta) | Unlimited (local) | $0.005-0.01/req (cloud) |

### Per-seat (mercado)

| Vendor | Individual | Team | Enterprise |
|--------|-----------|------|-----------|
| Snyk | Grátis | $25/dev/mês | Custom |
| Arthur AI | Grátis | $60/mês | Custom |
| prompt-armor (proposta) | Grátis (OSS) | $99/mês | $5K+/mês |

---

## 6. Go-to-Market Strategy

### Fase 1: Adoção (Agora → 6 meses)

**Objetivo:** 1K+ GitHub stars, 10K+ PyPI downloads

| Ação | Canal | Impacto |
|------|-------|---------|
| Show HN | Hacker News | Alto (developer audience) |
| Post no LinkedIn | 60K followers | Alto (AI companies) |
| awesome-llm-security lists | GitHub | Médio-alto (SEO) |
| Artigo técnico (blog/Medium) | Dev community | Médio |
| MCP integration guide para Claude | Anthropic ecosystem | Alto |
| Benchmark público vs concorrentes | GitHub/blog | Muito alto |

### Fase 2: Conversão (6-12 meses)

**Objetivo:** Primeiros $10K MRR

| Ação | Detalhe |
|------|---------|
| Dashboard Cloud (beta) | Waitlist → early access → paid |
| Council as a Service | Pay per council judgment |
| Threat Intel Feed | Subscription para attack DB updates |
| Enterprise outreach LATAM | Diferencial: suporte em PT, localização |

### Fase 3: Escala (12-24 meses)

**Objetivo:** $100K+ MRR ou acquisition

| Ação | Detalhe |
|------|---------|
| SOC 2 compliance | Necessário para enterprise US |
| Multi-cloud deploy | AWS Marketplace, GCP Marketplace |
| Partnership program | Integrações oficiais (LangChain, LlamaIndex, etc.) |
| Modelo proprietário premium | Fine-tuned em dados enterprise (não open-source) |

---

## 7. Vantagens Competitivas Específicas

### vs Lakera (principal concorrente)
- prompt-armor é auditável (Apache 2.0 vs proprietário)
- Roda 100% offline (Lakera precisa de internet)
- MCP nativo (Lakera não tem)
- Mais rápido (~27ms vs ~50ms)

### vs LLM Guard (agora Palo Alto)
- Fusão treinada vs scanners independentes
- 5 camadas coordenadas vs N scanners isolados
- Latência 10x menor
- Mas: Palo Alto tem distribuição enterprise massiva

### vs Prompt Security
- Grátis vs $50-120/mês desde o dia 1
- Open-source vs black box
- Self-hosted vs SaaS-only

### Vantagem de timing
- EU AI Act (agosto 2026) = urgência de compliance
- Agentic AI explosion = mais superfície de ataque
- Consolidação de mercado = janela para ser adquirido ou se estabelecer

---

## 8. Recomendação

### Modelo: Open-Core + Cloud

**Short-term (0-6 meses):**
1. Manter tudo open-source como está
2. Maximizar adoção: Show HN, LinkedIn, awesome-lists
3. Atingir 1K stars + 10K downloads
4. Construir waitlist para dashboard cloud

**Medium-term (6-12 meses):**
1. Lançar dashboard cloud (freemium)
2. Lançar threat intel feed (subscription)
3. Council as a Service
4. Primeiro revenue: target $5-10K MRR

**Long-term (12-24 meses):**
1. Enterprise sales (LATAM first, depois US)
2. AWS/GCP Marketplace
3. SOC 2 + compliance features
4. Ou: ser acquisition target para Cloudflare, Datadog, CrowdStrike

### Por que Open-Core e não SaaS puro

1. **Trust**: Em segurança, código auditável = credibilidade
2. **Distribuição**: 60K followers + open-source = viralização orgânica
3. **Community**: Contribuições melhoram o produto sem custo
4. **Defensibilidade**: Quem construiu integrações no OSS tem switching cost
5. **Exit optionality**: OSS com tração = acquisition target premium (Protect AI: 2.5M downloads → $500M exit)

### Riscos a mitigar

| Risco | Mitigação |
|-------|-----------|
| Cloud providers hostam sem pagar | Licença Apache permite isso, mas brand + velocidade de inovação protegem |
| Revenue demora | Manter lean, buscar grants (Anthropic, NVIDIA, EU AI funding) |
| Concorrência de Palo Alto/Cisco | Nicho em developer tools + MCP + LATAM (eles focam enterprise US) |
| Ser copiado | Velocidade > features. Ship fast, iterate faster |

---

## 9. Conclusão

O prompt-armor ocupa uma posição única no mercado: o único detector de prompt injection open-source com 5 camadas fundidas, MCP nativo, e latência sub-30ms. O mercado está em $2-4B com CAGR de 21-52%, consolidação ativa (3 aquisições em 18 meses), e pressão regulatória iminente (EU AI Act).

O modelo open-core é a escolha correta por três razões:
1. Em segurança, transparência gera confiança
2. A audiência de 60K+ followers é ideal para go-to-market grassroots
3. Open-source com tração é o melhor asset para negociação de acquisition

O caminho mais provável é: **adoção open-source → primeiros clientes enterprise (LATAM) → cloud managed → acquisition ou Series A**. Timing é favorável — a janela de 12-18 meses antes do EU AI Act é o momento ideal para estabelecer presença.
