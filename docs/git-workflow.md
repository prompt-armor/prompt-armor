# Git Workflow & Best Practices

Guia portável para projetos web com deploy contínuo via Vercel (ou similar).
Agnóstico de linguagem e framework — adaptável a qualquer stack.

---

## 1. Modelo de Branches

### Branches permanentes

| Branch | Papel | Deploy |
|--------|-------|--------|
| `main` | Produção — código estável, nunca commita direto | Production (URL fixa) |
| `dev` | Staging — integração contínua de features | Preview (URL fixa) |

### Branches temporárias (partem de `dev`)

| Prefixo | Quando usar | Exemplo |
|---------|-------------|---------|
| `feature/` | Nova funcionalidade | `feature/user-notifications` |
| `fix/` | Correção de bug | `fix/booking-duplicate` |
| `refactor/` | Refatoração sem mudança de comportamento | `refactor/auth-split` |
| `chore/` | Deps, config, CI, scripts | `chore/update-drizzle` |
| `docs/` | Apenas documentação | `docs/api-reference` |
| `hotfix/` | Correção urgente em produção | `hotfix/login-crash` |

### Regras absolutas

- **Nunca commitar direto em `main` ou `dev`** — sempre via Pull Request
- **Nunca force-push em `main`**
- Branch names em inglês, kebab-case, máximo ~4 palavras
- `hotfix/` é a única branch que parte de `main` e faz PR para `main`
- Após um hotfix em `main`, sincronizar `dev` imediatamente

---

## 2. Conventional Commits

Formato obrigatório para todos os commits:

```
tipo(escopo): descrição curta em inglês
```

### Tipos

| Tipo | Quando usar |
|------|-------------|
| `feat` | Nova funcionalidade |
| `fix` | Correção de bug |
| `refactor` | Refatoração (sem mudança de comportamento externo) |
| `style` | Formatação, espaços, vírgulas — sem mudança de lógica |
| `docs` | Apenas documentação |
| `test` | Adição ou correção de testes |
| `chore` | Tarefas de manutenção (deps, config, CI) |
| `perf` | Melhoria de performance |
| `ci` | Mudanças em pipelines de CI/CD |

### Escopo (opcional mas recomendado)

Use o nome do módulo, página ou domínio afetado:
`auth`, `api`, `db`, `ui`, `booking`, `dashboard`, `sidebar`, `e2e` etc.

### Exemplos válidos

```
feat(auth): add OAuth login with Google
fix(api): handle null phone in member update
refactor(db): extract pagination helper
chore(deps): upgrade drizzle-orm to 0.46
docs: update README with local setup instructions
test(booking): add E2E test for cancellation flow
```

### Regras de commit

- **Um commit = uma mudança lógica.** Nunca misturar feat + fix no mesmo commit.
- Descrição no imperativo, em inglês, sem ponto final: `"add user modal"` não `"added user modal."`
- Use o corpo do commit para explicar *por quê*, não *o quê* (o diff já mostra o quê).

---

## 3. Fluxo de Trabalho

### Feature / Fix

```bash
# 1. Partir sempre de dev atualizado
git checkout dev
git pull origin dev

# 2. Criar branch
git checkout -b feature/nome-da-feature

# 3. Desenvolver com commits atômicos
git add src/arquivo-modificado.ts
git commit -m "feat(scope): description"

# 4. Publicar e abrir PR para dev
git push -u origin feature/nome-da-feature
gh pr create --base dev --title "feat: ..." --body "..."

# 5. Após aprovação: squash merge via GitHub/CLI
gh pr merge <número> --squash --delete-branch
```

### Promoção dev → main (release)

```bash
# 1. Abrir PR de dev para main
gh pr create --base main --head dev --title "release: vX.Y.Z — ..."

# 2. Merge com merge commit (NÃO squash — preserva histórico)
gh pr merge <número> --merge --delete-branch=false

# 3. Atualizar main local
git checkout main && git pull origin main

# 4. Taggear a release
git tag -a vX.Y.Z -m "vX.Y.Z — Descrição curta"
git push origin vX.Y.Z
```

### Hotfix (urgência em produção)

```bash
# 1. Partir de main
git checkout main && git pull origin main
git checkout -b hotfix/descricao-do-problema

# 2. Corrigir e commitar
git commit -m "fix(scope): critical fix description"

# 3. PR direto para main
gh pr create --base main
gh pr merge <número> --squash --delete-branch

# 4. Taggear patch version
git checkout main && git pull origin main
git tag -a vX.Y.Z -m "vX.Y.Z — hotfix: ..."
git push origin vX.Y.Z

# 5. Sincronizar dev com a correção
git checkout dev && git pull origin dev
git merge main
git push origin dev
```

---

## 4. Estratégia de Merge

| Merge | Estratégia | Motivo |
|-------|-----------|--------|
| `feature/*` → `dev` | **Squash merge** | Histórico limpo em dev; um squash = uma feature |
| `dev` → `main` | **Merge commit** | Preserva rastreabilidade completa de quando cada release foi feita |
| `hotfix/*` → `main` | **Squash merge** | Correção pontual, não precisa de histórico de WIP |

---

## 5. Versionamento Semântico (SemVer)

Formato: `vMAJOR.MINOR.PATCH`

| Incremento | Quando | Exemplo |
|-----------|--------|---------|
| `PATCH` (0.0.X) | Bug fix sem quebrar API/UX | `v2.1.1` |
| `MINOR` (0.X.0) | Nova feature retrocompatível | `v2.2.0` |
| `MAJOR` (X.0.0) | Breaking change ou grande reescrita | `v3.0.0` |

### Regras de tag

- Tags sempre em `main`, nunca em branches temporárias
- Formato anotado (`-a`), nunca lightweight: `git tag -a v1.0.0 -m "mensagem"`
- Sempre fazer push da tag explicitamente: `git push origin v1.0.0`
- Manter `CHANGELOG.md` atualizado a cada release

### Estrutura do CHANGELOG

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Adicionado
- ...

### Alterado
- ...

### Corrigido
- ...

### Removido
- ...
```

---

## 6. Integração com Claude Code (CLAUDE.md)

Para projetos que usam Claude Code como agente de desenvolvimento, incluir uma seção de Git Workflow no `CLAUDE.md` do projeto. Isso garante que o agente siga as mesmas regras automaticamente.

### Seção recomendada no CLAUDE.md

```markdown
## Git Workflow (OBRIGATÓRIO)

### Branches
| Branch | Papel |
|--------|-------|
| `main` | Produção — nunca commitar direto |
| `dev` | Staging — recebe merges de feature branches via PR |
| `feature/*`, `fix/*` | Trabalho isolado |

### Fluxo
1. Feature branches partem de `dev`: `git checkout dev && git checkout -b feature/nome`
2. PR para `dev` com squash merge
3. Merge manual `dev → main` quando estável (merge commit)
4. Taggear releases em `main` com SemVer

### Commits — Conventional Commits
tipo(escopo): descrição em inglês

Tipos: feat, fix, refactor, style, docs, test, chore, perf, ci

### Regras estritas
- NUNCA commitar direto em main ou dev
- NUNCA force-push em main
- NUNCA fazer PR de feature direto para main
- Squash merge: feature → dev
- Merge commit: dev → main
```

### Como o agente deve operar

O Claude Code deve executar o seguinte fluxo em toda sessão de implementação:

**Antes de começar:**
```bash
git checkout dev && git pull origin dev
git checkout -b feature/nome-da-feature
```

**Durante:**
- Commits atômicos com Conventional Commits
- Um commit por mudança lógica

**Ao finalizar:**
```bash
git push -u origin feature/nome-da-feature
gh pr create --base dev --title "..." --body "..."
# Informar o usuário que o PR está pronto
```

**Promoção para produção (somente quando o usuário pedir):**
```bash
gh pr create --base main --head dev
gh pr merge <número> --merge --delete-branch=false
git checkout main && git pull origin main
git tag -a vX.Y.Z -m "..."
git push origin vX.Y.Z
```

---

## 7. Pull Request — Boas Práticas

### Template de PR

```markdown
## O que foi feito
- Bullet points das mudanças principais

## Por que foi feito
- Contexto e motivação

## Como testar
- [ ] Passo 1
- [ ] Passo 2
- [ ] Passo N

## Screenshots (se aplicável)
```

### Checklist antes de abrir PR

- [ ] Branch parte de `dev` (ou `main` para hotfix)
- [ ] Commits seguem Conventional Commits
- [ ] Nenhum arquivo sensível commited (`.env`, secrets, credenciais)
- [ ] Código compila sem erros (`npm run build` ou equivalente)
- [ ] Testes passam (`npm test` ou equivalente)
- [ ] CHANGELOG atualizado (se for release)

---

## 8. Proteção de Branches (Recomendado)

Configurar no GitHub/GitLab:

**`main`:**
- Require PR before merging ✅
- Require status checks (CI) ✅
- Prevent force-push ✅
- Prevent deletion ✅

**`dev`:**
- Require PR before merging ✅
- Prevent force-push ✅

> Em repositórios privados do GitHub Free, branch protection não está disponível.
> Nesse caso, a disciplina de equipe substitui as regras automáticas.

---

## 9. Comandos de Referência Rápida

```bash
# Ver log compacto da branch atual vs dev
git log --oneline feature/minha-feature ^dev

# Ver diferença entre dev e main
git diff dev..main --stat

# Listar todas as tags ordenadas
git tag -l --sort=-v:refname | head -10

# Desfazer último commit (mantendo as mudanças)
git reset HEAD~1 --soft

# Criar tag anotada e publicar
git tag -a v1.2.3 -m "v1.2.3 — descrição" && git push origin v1.2.3

# Deletar branch local e remota
git branch -d feature/nome
git push origin --delete feature/nome

# Listar PRs abertos (gh CLI)
gh pr list

# Ver status de um PR
gh pr view <número>

# Merge squash e delete branch
gh pr merge <número> --squash --delete-branch

# Merge commit (dev → main)
gh pr merge <número> --merge --delete-branch=false
```

---

## 10. Armadilhas Comuns

| Situação | Errado | Certo |
|----------|--------|-------|
| Commitar em main | `git commit` direto | Sempre via PR |
| Sincronizar após hotfix | Esquecer de fazer merge em `dev` | `git checkout dev && git merge main && git push` |
| Taggear antes do merge | Tag em feature branch | Tag sempre em `main` pós-merge |
| Squash em dev→main | Perde rastreabilidade | Usar `--merge` (merge commit) |
| Force-push em branch compartilhada | `git push --force` | Nunca em `dev`/`main`; usar `--force-with-lease` em branches pessoais se absolutamente necessário |
| Misturar feat + fix num commit | Commit gigante | Commits atômicos |
| Commitar `.env` | `git add .` sem verificar | Usar `.gitignore` + revisar `git status` antes |
