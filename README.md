# Explorador de Domínios

## Descrição

**O explorador de domínios** é um script Python desenvolvido para realizar análises detalhadas de domínios e identificar potenciais vulnerabilidades de segurança. Ele combina múltiplas técnicas de reconhecimento para coletar informações sobre DNS, WHOIS, segurança de SSL, geolocalização de IPs, reputação de domínio e muito mais.

Este projeto é ideal para profissionais de segurança da informação, pesquisadores e entusiastas interessados em realizar análises abrangentes de domínios, visando identificação de riscos e possíveis pontos de ataque.

---

## Funcionalidades

### Análise Básica de Domínios

1. **Informações WHOIS**: Extrai informações detalhadas sobre o domínio, como registrador, datas de criação/expiração e servidores DNS.
2. **Verificação de Registros DNS**: Obtém registros DNS como A, MX, CNAME, TXT, SOA e CAA.

### Segurança SSL/TLS Avançada

3. **Análise de Segurança SSL/TLS**: Inspeciona detalhes do certificado SSL, validade, emissor e ciphers usados.
4. **Verificação de Revogação de Certificados**: Verifica status CRL/OCSP para detectar certificados revogados.
5. **Análise da Cadeia de Certificados**: Examina a cadeia completa de certificados e sua confiabilidade.
6. **Verificação de Políticas de Segurança**: Analisa políticas HSTS, CSP e outras configurações de segurança.
7. **Detecção de Certificados Auto-assinados**: Identifica certificados auto-assinados ou inválidos.

### Headers e Políticas de Segurança

8. **Verificação de Cabeçalhos de Segurança**: Identifica cabeçalhos importantes como HSTS, CSP, X-Frame-Options e mais.

### Análise de Infraestrutura

9. **Varredura de Diretórios Comuns**: Detecta diretórios sensíveis e arquivos críticos como `.git`, `phpinfo.php`, `robots.txt`.
10. **Geolocalização de IPs**: Determina a localização geográfica associada ao IP do domínio.
11. **Detecção de Tecnologias Web**: Identifica tecnologias como WordPress, Joomla, React, Angular e outras.
12. **Segurança de E-mails**: Verifica registros MX, SPF e DMARC para segurança de e-mail.
13. **Análise de Subdomain Takeover**: Detecta potenciais vulnerabilidades relacionadas à posse de subdomínios.
14. **Varredura de Portas Comuns**: Escaneia portas como 80, 443, 22, 3306, entre outras.
15. **Reputação do Domínio**: Consulta APIs como VirusTotal para verificar reputação.

---

## Requisitos

- **Python 3.6+**
- Bibliotecas Python necessárias (instale com `pip`):
  ```bash
  pip install whois dnspython requests colorama geoip2 tldextract nmap python-nmap
  ```
- Banco de dados GeoIP: `GeoLite2-Country.mmdb`

---

## Uso

### Análise Completa

1. Clone o repositório ou salve o script em sua máquina.
2. Execute o script principal:
   ```bash
   python explorador-dns.py
   ```
3. Insira o domínio a ser analisado quando solicitado ou digite `sair` para encerrar.

### Teste das Novas Funcionalidades de Certificados

Para testar especificamente as novas funcionalidades de certificados SSL/TLS:

```bash
python test_certificate_features.py
```

Este script de teste permite:

- Testar domínios predefinidos (Google, GitHub, Example)
- Testar um domínio específico de sua escolha
- Verificar cada funcionalidade individualmente

---

## Exemplo de Saída

```
=== Analisador de Domínios Avançado v2.0 ===

Digite o domínio para análise (ou 'sair' para encerrar): example.com

==================================================
Informações WHOIS
==================================================
Domínio: example.com
Registrador: ICANN
Data de Criação: 1995-08-13
Data de Expiração: 2024-08-13
Servidores DNS:
  - ns1.example.com
  - ns2.example.com

==================================================
Registros DNS
==================================================
... (continua)
```

---

## Novas Funcionalidades de Certificados SSL/TLS

### 1. Verificação de Revogação de Certificados (CRL/OCSP)

- **CRL (Certificate Revocation List)**: Verifica se há distribuição de listas de revogação disponíveis
- **OCSP (Online Certificate Status Protocol)**: Identifica responderes OCSP para verificação em tempo real
- **Status de Revogação**: Detecta se o certificado está na lista de revogados

### 2. Análise da Cadeia de Certificados

- **Cadeia Completa**: Examina todos os certificados da cadeia (domínio → intermediário → CA raiz)
- **Validação de Confiança**: Verifica se a CA raiz é reconhecida como confiável
- **Estrutura da Cadeia**: Analisa se a cadeia segue padrões recomendados
- **Detecção de Problemas**: Identifica cadeias muito curtas ou não padrão

### 3. Verificação de Políticas de Segurança

- **HSTS (HTTP Strict Transport Security)**:
  - Verifica configuração de `max-age`
  - Analisa presença de `includeSubDomains` e `preload`
  - Recomendações de configuração
- **CSP (Content Security Policy)**:
  - Verifica diretivas essenciais (`default-src`, `script-src`, `style-src`)
  - Detecta configurações inseguras (`unsafe-inline`, `unsafe-eval`)
  - Identifica implementações seguras (nonce, hash)
- **Outras Políticas**: X-Frame-Options, X-Content-Type-Options, Referrer-Policy

### 4. Detecção de Certificados Auto-assinados/Inválidos

- **Auto-assinados**: Detecta certificados onde o emissor é igual ao assunto
- **Validade Temporal**: Verifica se o certificado está dentro do período de validade
- **SANs (Subject Alternative Names)**: Confirma se o domínio está listado nos SANs
- **Força da Criptografia**: Analisa cipher suites e versões TLS
- **Algoritmos de Assinatura**: Identifica algoritmos fracos (MD5, SHA1) vs. fortes (SHA256+)

## Configurações Adicionais

As configurações padrão podem ser personalizadas no método `_default_config`, incluindo:

- **Timeout da conexão**
- **Número máximo de threads**
- **APIs de reputação**
- **Portas comuns para escaneamento**

---

## Avisos

- Use com responsabilidade e ética, respeitando políticas de uso aceitável.
- Pode requerer permissões administrativas para varredura de portas.
- Algumas funcionalidades exigem acesso a APIs externas, como VirusTotal.

---

## Licença

Este projeto é disponibilizado sob a [Licença MIT](LICENSE). Use, modifique e distribua conforme necessário.

---

Aproveite o AdvancedDomainAnalyzer para suas análises!
