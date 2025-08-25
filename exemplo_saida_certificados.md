# Exemplo de Saída - Novas Funcionalidades de Certificados SSL/TLS

## 1. Verificação de Revogação de Certificados (CRL/OCSP)

```
==================================================
Verificação de Revogação de Certificados
==================================================
Verificando status de revogação...
✓ Verificação CRL: CRL disponível em 2 local(is)
✓ Verificação OCSP: Responder OCSP: http://ocsp.digicert.com
✓ Certificado não está na lista de revogados
```

## 2. Análise da Cadeia de Certificados

```
==================================================
Análise da Cadeia de Certificados
==================================================
Cadeia de Certificados (3 certificados):

Certificado 1:
  Assunto:
    commonName: example.com
    organizationName: Example Organization
  Emissor:
    commonName: DigiCert Inc
    organizationName: DigiCert Inc
  Válido: 2024-01-01 00:00:00 até 2025-01-01 00:00:00

Certificado 2:
  Assunto:
    commonName: DigiCert Inc
    organizationName: DigiCert Inc
  Emissor:
    commonName: DigiCert Inc
    organizationName: DigiCert Inc
  Válido: 2020-01-01 00:00:00 até 2030-01-01 00:00:00
  ✓ Certificado raiz (self-signed)

Análise de Confiança da Cadeia:
✓ CA raiz confiável: DigiCert Inc
✓ Cadeia padrão (domínio → intermediário → CA raiz)
```

## 3. Verificação de Políticas de Segurança

```
==================================================
Verificação de Políticas de Segurança
==================================================
Políticas de Segurança Detectadas:

✓ HSTS Configurado:
  Valor: max-age=31536000; includeSubDomains; preload
  ✓ max-age adequado: 31536000 segundos
  ✓ includeSubDomains ativado
  ✓ preload ativado

✓ CSP Configurado:
  Valor: default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self'
  ✓ default-src configurado
  ✓ script-src configurado
  ✓ style-src configurado
  ✓ nonce implementado para scripts inline

Outras Políticas de Segurança:
  ✓ X-Frame-Options: Previne clickjacking
  ✓ X-Content-Type-Options: Previne MIME type sniffing
  ✓ X-XSS-Protection: Proteção XSS do navegador
  ✓ Referrer-Policy: Controle de informações de referência
  ⚠ Permissions-Policy: Controle de recursos do navegador (não configurado)
```

## 4. Detecção de Certificados Auto-assinados/Inválidos

```
==================================================
Detecção de Certificados Auto-assinados/Inválidos
==================================================
Análise do Certificado:

✓ Certificado não é auto-assinado
✓ Certificado válido por mais 300 dias

✓ Domínio encontrado nos SANs

Informações de Criptografia:
  Cipher Suite: TLS_AES_256_GCM_SHA384
  ✓ Cipher Suite muito forte (256 bits)

Versão TLS: TLSv1.3
  ✓ Versão TLS mais recente e segura

Algoritmo de Assinatura: sha256WithRSAEncryption
  ✓ Algoritmo de assinatura forte
```

## Resumo das Verificações

### ✅ Funcionalidades Implementadas com Sucesso:

1. **Verificação CRL/OCSP**: Detecta mecanismos de revogação disponíveis
2. **Análise de Cadeia**: Examina toda a cadeia de certificados
3. **Políticas de Segurança**: Analisa HSTS, CSP e outros headers
4. **Detecção de Problemas**: Identifica certificados problemáticos

### 🔍 Recursos de Análise:

- **Validação Temporal**: Verifica datas de validade e expiração
- **Análise de Confiança**: Identifica CAs confiáveis vs. suspeitas
- **Configurações de Segurança**: Avalia políticas HSTS e CSP
- **Força Criptográfica**: Analisa cipher suites e algoritmos
- **Conformidade**: Verifica padrões de segurança recomendados

### 📊 Score de Segurança:

- **HSTS**: 100% (configuração completa)
- **CSP**: 90% (implementação segura com nonce)
- **Certificados**: 95% (cadeia confiável e válida)
- **Criptografia**: 100% (TLS 1.3 + cipher forte)

### 🚨 Alertas e Recomendações:

- Implementar Permissions-Policy para controle de recursos
- Monitorar expiração de certificados (300 dias restantes)
- Considerar renovação automática de certificados
