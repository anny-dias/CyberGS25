# Laboratório de Vulnerabilidades em Python (Flask)

**Objetivo do trabalho**
Demonstrar, explicar e corrigir quatro vulnerabilidades clássicas em aplicações web, provando o ciclo completo: **conceito → prova de ataque (PoC) → correção → automação de detecção em CI/CD**. Entrega pensada para avaliação acadêmica: clareza técnica, evidências dos testes e configuração do pipeline DevSecOps.

---

## Resumo executivo 

* Aplicação **Flask** com rotas deliberadamente vulneráveis (`/vuln/...`) e rotas corrigidas correspondentes (`/safe/...`).
* Vulnerabilidades abordadas:

  1. **SQL Injection**
  2. **Broken Access Control (Quebra de Controle de Acesso)**
  3. **Insecure Deserialization (pickle)**
  4. **Command Injection**
* Scripts e passos para reproduzir ataques (PoC) e validar correções.
* Arquivos de automação: `.semgrep.yml`, exemplos de workflows GitHub Actions (`.github/workflows/ci.yml` e `zap-baseline.yml`) para SAST, SCA e DAST.
* `seed.sql` para popular o banco de dados SQLite usado nos testes.
* README técnico.

---

## Estrutura do repositório

```
vulns-lab/
├─ app.py                 # Aplicação Flask (rotas vulneráveis e seguras)
├─ seed.sql               # Popula lab.db (users: alice/admin, bob/user)
├─ requirements.txt
├─ make_pickle.py         # (helper) gera payload pickle
├─ .semgrep.yml           # Regras de exemplo para SAST (Semgrep)
├─ .github/
│  └─ workflows/
│     ├─ ci.yml           # Pipeline SAST + SCA (exemplo)
│     └─ zap-baseline.yml # Pipeline DAST (exemplo)
├─ .gitignore
└─ README.md              # Este arquivo
```

---

## Ambiente e pré-requisitos (instalação do zero)

### Requisitos mínimos

* Python 3.10+ instalado
* Git
* Git Bash (recomendado no Windows) ou PowerShell / terminal Unix
* (Opcional, para DAST) Docker ou OWASP ZAP instalado
* Conexão à internet para instalar dependências

### Passo a passo — criar ambiente e instalar

1. Clone o repositório (ou copie os arquivos locais):

   ```bash
   git clone https://github.com/anny-dias/CyberGS25.git
   cd vulns-lab
   ```

2. Criar e ativar virtual environment:

   * **Git Bash (Windows)**:

     ```bash
     python -m venv .venv
     source .venv/Scripts/activate
     ```
   * **PowerShell (Windows)**:

     ```powershell
     python -m venv .venv
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
     .\.venv\Scripts\Activate.ps1
     ```
   * **Linux / macOS**:

     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. Instalar dependências:

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Iniciar a aplicação:

   ```bash
   python app.py
   ```

   A aplicação será disponibilizada em `http://127.0.0.1:5000/`.

---

## Como o app está organizado 

* `app.py` contém:

  * Helpers de conexão SQLite (`lab.db`).
  * Rotas vulneráveis: `/vuln/sql/users`, `/vuln/admin/delete`, `/vuln/pickle`, `/vuln/ping`.
  * Rotas seguras correspondentes: `/safe/sql/users`, `/safe/admin/delete`, `/safe/json`, `/safe/ping`.
  * Simulação de autenticação: header `X-User` (valor `alice` → admin; `bob` → user). Essa simulação é apenas didática — em produção usar JWT/OAuth/RBAC.

---

## Vulnerabilidades: descrição, PoC (ataque) e correção

### 1) SQL Injection

* **Conceito:** entrada do usuário concatenada diretamente em SQL permite alterar a consulta.
* **Risco:** vazamento ou modificação de dados, bypass de autenticação.
* **PoC (vulnerável):**

  ```bash
  curl --get --data-urlencode "q=' OR '1'='1" "http://127.0.0.1:5000/vuln/sql/users"
  ```

  Pode retornar todos os registros do banco.
* **Correção (defesa):** usar parâmetros/prepared statements (placeholders `?`) — rota `/safe/sql/users`.

---

### 2) Broken Access Control

* **Conceito:** ausência de checagem de autorização para operações sensíveis.
* **Risco:** qualquer usuário pode executar ações administrativas (ex.: deletar usuários).
* **PoC (vulnerável):**

  ```bash
  curl -X DELETE "http://127.0.0.1:5000/vuln/admin/delete?user=bob"
  ```
* **Correção:** validar papel/autorização antes da ação; exemplo: decorator `@require_admin` — rota `/safe/admin/delete`.
* **Teste (defesa):**

  ```bash
  # usuário comum -> 403
  curl -X DELETE -H "X-User: bob" "http://127.0.0.1:5000/safe/admin/delete?user=alice"

  # admin -> operação permitida
  curl -X DELETE -H "X-User: alice" "http://127.0.0.1:5000/safe/admin/delete?user=bob"
  ```

---

### 3) Insecure Deserialization (pickle)

* **Conceito:** desserializar objetos binários não confiáveis (pickle) pode executar código arbitrário.
* **Risco:** execução remota de código (RCE) — severo.
* **PoC (vulnerável):**

  ```bash
  python - <<'PY'
  import pickle, requests
  payload = pickle.dumps({"msg":"oi"})
  r = requests.post("http://127.0.0.1:5000/vuln/pickle", data=payload)
  print(r.status_code, r.text)
  PY
  ```
* **Correção:** **nunca** usar `pickle` para dados do cliente; usar JSON + validação de esquema (rota `/safe/json`).

---

### 4) Command Injection

* **Conceito:** construir comandos shell concatenando input do usuário.
* **Risco:** execução de comandos arbitrários no servidor.
* **PoC (vulnerável):**

  ```bash
  curl --get --data-urlencode "host=127.0.0.1;whoami" "http://127.0.0.1:5000/vuln/ping"
  ```
* **Correção:** validação whitelist/regex do input e uso de `subprocess.run([...], shell=False)` com lista de argumentos (rota `/safe/ping`).

---

## Execução dos testes — passo a passo (comandos prontos)

> Recomendado: use Git Bash no Windows. Adapte para PowerShell se necessário.

1. **Ver rotas principais**

   ```bash
   curl "http://127.0.0.1:5000/"
   ```

2. **SQL Injection**

   * Vulnerável:

     ```bash
     curl --get --data-urlencode "q=' OR '1'='1" "http://127.0.0.1:5000/vuln/sql/users"
     ```
   * Segura:

     ```bash
     curl --get --data-urlencode "q=' OR '1'='1" "http://127.0.0.1:5000/safe/sql/users"
     ```

3. **Broken Access Control**

   * Vulnerável:

     ```bash
     curl -X DELETE "http://127.0.0.1:5000/vuln/admin/delete?user=bob"
     ```
   * Segura (falha para user comum):

     ```bash
     curl -X DELETE -H "X-User: bob" "http://127.0.0.1:5000/safe/admin/delete?user=alice"
     ```
   * Segura (admin):

     ```bash
     curl -X DELETE -H "X-User: alice" "http://127.0.0.1:5000/safe/admin/delete?user=bob"
     ```

4. **Insecure Deserialization**

   * Vulnerável (PoC usando requests):

     ```bash
     python - <<'PY'
     import pickle, requests
     payload = pickle.dumps({"msg":"oi"})
     r = requests.post("http://127.0.0.1:5000/vuln/pickle", data=payload)
     print(r.status_code, r.text)
     PY
     ```
   * Segura:

     ```bash
     curl -X POST http://127.0.0.1:5000/safe/json -H "Content-Type: application/json" -d '{"msg":"oi"}'
     ```

5. **Command Injection**

   * Vulnerável:

     ```bash
     curl --get --data-urlencode "host=127.0.0.1;whoami" "http://127.0.0.1:5000/vuln/ping"
     ```
   * Segura:

     ```bash
     curl --get --data-urlencode "host=127.0.0.1" "http://127.0.0.1:5000/safe/ping"
     ```

6. **Reset do banco (se necessário)**

   * Pare o servidor (Ctrl+C) e execute:

     ```bash
     rm lab.db
     python app.py
     ```
   * O arquivo será recriado usando `seed.sql`.

---

## Automação de detecção (CI/CD)

### Ferramentas indicadas (o que cada uma faz)

* **Semgrep (SAST):** busca padrões inseguros no código (ex.: `pickle.loads`, `os.system`, concatenação em SQL).
* **Bandit (SAST):** analisa código Python por problemas de segurança comuns.
* **pip-audit / Safety (SCA):** verifica bibliotecas por CVEs.
* **OWASP ZAP (DAST):** varredura dinâmica contra a aplicação rodando (staging/PR).

### Executar localmente (comandos)

```bash
# Semgrep
semgrep --config .semgrep.yml .

# Bandit
bandit -r . -x .venv -ll

# pip-audit
pip-audit
```

### GitHub Actions (exemplo de CI)

* `ci.yml` roda Semgrep, Bandit e pip-audit em push/PR.
* `zap-baseline.yml` inicia app e executa ZAP baseline (workflow dispatch ou em PR contra staging).




---
## Referências (sugestões para leitura)

* OWASP Top 10 — explicações e exemplos.
* Documentação Semgrep, Bandit, pip-audit, OWASP ZAP.
* Documentação oficial Flask e sqlite3.

---

## Contato / Autor

* Autores do projeto: Anny Carolina Andrade Dias (RM98295), Fernanda Kaory Saito (RM551104) e Pedro Emerici Gava (RM551043). 


