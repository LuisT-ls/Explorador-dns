# 🚀 Novas Funcionalidades de Segurança - Explorador DNS

## 📋 Visão Geral

Este documento descreve as 4 novas funcionalidades de segurança implementadas no Explorador DNS, que fornecem uma análise abrangente de domínios para detectar ameaças e avaliar reputação.

## 🔍 1. Verificação em Múltiplas Blacklists

### Funcionalidade

Verifica se o domínio está listado em múltiplas blacklists conhecidas, incluindo:

- **Spamhaus** (múltiplas listas: zen, sbl, xbl, pbl)
- **SURBL** (multi.surbl.org)
- **URIBL** (black.uribl.com)
- **DNSBL Sorbs** (dnsbl.sorbs.net)
- **Barracuda** (b.barracudacentral.org)
- **SpamCop** (bl.spamcop.net)

### Como Funciona

1. Resolve o IP do domínio
2. Converte o IP para formato reverso (ex: 1.2.3.4 → 4.3.2.1)
3. Consulta cada blacklist usando DNS
4. Consolida os resultados e exibe um resumo

### Saída

- Status de cada blacklist (BLOQUEADO/LIMPO/ERRO)
- Contagem total de blacklists que bloquearam
- Classificação de risco baseada no número de blacklists

## 🦠 2. Análise de Histórico de Malware

### Funcionalidade

Analisa o domínio em busca de indicadores de atividade maliciosa:

#### URLs Suspeitas

- Verifica caminhos comuns para downloads suspeitos
- Detecta arquivos executáveis (.exe, .bat, .scr, etc.)
- Identifica URLs de atualização suspeitas

#### Padrões de Malware

- Busca por palavras-chave suspeitas no conteúdo
- Detecta padrões de engenharia social
- Identifica tentativas de distribuição de malware

#### Similaridade de Domínios

- Calcula similaridade com domínios maliciosos conhecidos
- Usa algoritmo de Levenshtein para detecção
- Identifica possíveis tentativas de typosquatting

#### Arquivos Suspeitos

- Verifica acesso a arquivos de log e backup
- Detecta arquivos temporários expostos
- Identifica arquivos de configuração sensíveis

### Como Funciona

1. Faz requisições HTTP para caminhos suspeitos
2. Analisa o conteúdo HTML em busca de padrões
3. Calcula similaridade com domínios conhecidos
4. Verifica acessibilidade de arquivos sensíveis

## 🎣 3. Verificação de Phishing e Fraudes

### Funcionalidade

Detecta tentativas de phishing e fraudes:

#### Indicadores de Phishing

- Palavras-chave suspeitas ("verify account", "security alert")
- Formulários de login suspeitos
- Campos de segurança ausentes

#### Tentativas de Spoofing

- Detecção de typosquatting
- Caracteres confusos (homoglyphs)
- Imitação de serviços conhecidos

#### Verificação Externa

- Consulta ao PhishTank (API pública)
- Verificação de status de phishing
- Histórico de denúncias

#### Padrões de Fraude

- Promessas de dinheiro fácil
- Ofertas de investimento suspeitas
- Alertas de segurança falsos

### Como Funciona

1. Analisa o conteúdo da página inicial
2. Verifica similaridade com serviços legítimos
3. Consulta bases de dados de phishing
4. Identifica padrões de fraude no conteúdo

## 📊 4. Score de Reputação Baseado em Múltiplas Fontes

### Funcionalidade

Calcula um score de reputação de 0-100 baseado em múltiplos fatores:

#### Categorias de Avaliação

- **Blacklists** (25%): Penalização por cada blacklist
- **Malware** (25%): Indicadores de atividade maliciosa
- **Phishing** (20%): Indicadores de phishing e fraude
- **APIs Externas** (20%): Reputação em serviços terceiros
- **Idade do Domínio** (5%): Histórico e maturidade
- **Configurações de Segurança** (5%): Headers e políticas

#### APIs de Reputação

- **URLhaus**: Verificação de malware (sem API key)
- **PhishTank**: Verificação de phishing
- **VirusTotal**: Análise completa (requer API key)
- **IBM X-Force**: Reputação corporativa (requer API key)

### Como Funciona

1. Coleta dados de todas as verificações anteriores
2. Calcula score individual para cada categoria
3. Aplica pesos para calcular score final
4. Classifica o domínio por nível de risco

### Classificação de Risco

- **80-100**: EXCELENTE - Baixo risco
- **60-79**: BOM - Risco moderado
- **40-59**: REGULAR - Risco alto
- **0-39**: RUIM - Altíssimo risco

## 🛠️ Configuração e Uso

### Dependências

```bash
pip install -r requirements.txt
```

### Execução

```bash
python explorador-dns.py
```

### Funcionalidades Automáticas

As novas funcionalidades são executadas automaticamente durante a análise completa do domínio.

## 📝 Logs e Relatórios

### Arquivo de Log

- Todas as verificações são registradas em `domain_analysis.log`
- Inclui timestamps e níveis de log
- Útil para auditoria e troubleshooting

### Saída no Terminal

- Formatação colorida para fácil identificação
- Emojis para categorização visual
- Resumos detalhados de cada verificação

## 🔧 Personalização

### Configuração de Blacklists

Edite `BLACKLIST_SERVICES` para adicionar/remover serviços.

### Padrões de Malware

Modifique `MALWARE_INDICATORS` para ajustar detecções.

### APIs de Reputação

Configure `REPUTATION_APIS` com suas chaves de API.

## ⚠️ Considerações de Segurança

### Rate Limiting

- Respeite os limites das APIs externas
- Implemente delays entre verificações
- Use chaves de API quando disponíveis

### Privacidade

- Não compartilhe logs com informações sensíveis
- Configure timeouts apropriados
- Monitore o uso de recursos

### Legitimidade

- Use apenas para domínios próprios ou autorizados
- Respeite os termos de serviço das APIs
- Não abuse dos serviços gratuitos

## 🚀 Próximos Passos

### Melhorias Futuras

- Integração com mais APIs de reputação
- Machine learning para detecção de padrões
- Interface web para análise em lote
- Relatórios em PDF/HTML
- Integração com SIEMs

### Contribuições

- Adicione novas blacklists
- Implemente algoritmos de detecção
- Melhore a precisão dos scores
- Adicione suporte a mais idiomas

---

**Desenvolvido com ❤️ para a comunidade de segurança**
