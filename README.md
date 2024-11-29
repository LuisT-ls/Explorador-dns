# AdvancedDomainAnalyzer - README

## Descrição

**AdvancedDomainAnalyzer** é um poderoso script Python desenvolvido para realizar análises detalhadas de domínios e identificar potenciais vulnerabilidades de segurança. Ele combina múltiplas técnicas de reconhecimento para coletar informações sobre DNS, WHOIS, segurança de SSL, geolocalização de IPs, reputação de domínio e muito mais.

Este projeto é ideal para profissionais de segurança da informação, pesquisadores e entusiastas interessados em realizar análises abrangentes de domínios, visando identificação de riscos e possíveis pontos de ataque.

---

## Funcionalidades

1. **Informações WHOIS**: Extrai informações detalhadas sobre o domínio, como registrador, datas de criação/expiração e servidores DNS.
2. **Verificação de Registros DNS**: Obtém registros DNS como A, MX, CNAME, TXT, SOA e CAA.
3. **Análise de Segurança SSL/TLS**: Inspeciona detalhes do certificado SSL, validade, emissor e ciphers usados.
4. **Verificação de Cabeçalhos de Segurança**: Identifica cabeçalhos importantes como HSTS, CSP, X-Frame-Options e mais.
5. **Varredura de Diretórios Comuns**: Detecta diretórios sensíveis e arquivos críticos como `.git`, `phpinfo.php`, `robots.txt`.
6. **Geolocalização de IPs**: Determina a localização geográfica associada ao IP do domínio.
7. **Detecção de Tecnologias Web**: Identifica tecnologias como WordPress, Joomla, React, Angular e outras.
8. **Segurança de E-mails**: Verifica registros MX, SPF e DMARC para segurança de e-mail.
9. **Análise de Subdomain Takeover**: Detecta potenciais vulnerabilidades relacionadas à posse de subdomínios.
10. **Varredura de Portas Comuns** *(Opcional)*: Escaneia portas como 80, 443, 22, 3306, entre outras.
11. **Reputação do Domínio** *(Opcional)*: Consulta APIs como VirusTotal para verificar reputação.

---

## Requisitos

- **Python 3.6+**
- Bibliotecas Python necessárias (instale com `pip`):
  ```bash
  pip install whois dnspython requests colorama geoip2 tldextract nmap python-nmap
  ```
- Banco de dados GeoIP (opcional): `GeoLite2-Country.mmdb`

---

## Uso

1. Clone o repositório ou salve o script em sua máquina.
2. Execute o script:
   ```bash
   python script_name.py
   ```
3. Insira o domínio a ser analisado quando solicitado ou digite `sair` para encerrar.

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