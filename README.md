# PA Secure E-Vote

Sistema de votação eletrónica segura desenvolvido em Java para a disciplina de Programação Avançada.

## Descrição do Projeto

O **pa-secure-evote** é um sistema completo de votação eletrónica que garante anonimato, confidencialidade e verificabilidade dos votos. O sistema implementa criptografia avançada, certificados digitais X.509 e comunicação segura entre 5 entidades principais.
O sistema foi projetado para garantir que nenhum voto possa ser associado ao eleitor que o submeteu, mantendo simultaneamente a integridade do processo eleitoral através de múltiplas camadas de segurança criptográfica.

## Funcionalidades Principais

- Emissão e validação de certificados digitais X.509
- Processamento paralelo com controlo de fases de eleição
- Encriptação híbrida de votos (AES + RSA)
- Sistema de threshold cryptography (3/5 shares)
- Certificate Revocation List (CRL)
- Mix Network para anonimização de votos
- Logging estruturado com contexto de transação
- Carregamento de candidatos via ficheiro de configuração

## Tecnologias Utilizadas

- **Java** - Linguagem principal
- **BouncyCastle** - Criptografia e certificados X.509
- **SLF4J + Logback** - Logging estruturado
- **JUnit + Mockito** - Testes unitários
- **JaCoCo** - Relatórios de cobertura
- **Maven** - Gestão de dependências

## Pré-requisitos

- Java JDK 17 ou superior
- Maven 3.6+

## Como Executar

- Abrir o projeto no IDE
- Executar a classe `VotingSystem.java`

## Entidades do Sistema

- **Registration Authority (AR)** - Emite certificados X.509
- **Voting Server (SV)** - Autentica eleitores
- **Ballot Box (UE)** - Armazena votos encriptados
- **Tallying Authority (AA)** - Desencripta e conta votos
- **Voting System** - Coordena todo o processo

## Fluxo de Votação

### 1. Fase de Registo
- Registo de eleitores elegíveis
- Emissão de certificados X.509

### 2. Fase de Votação
- Autenticação de eleitores
- Submissão de votos encriptados

### 3. Fase de Apuramento
- Desencriptação com threshold cryptography
- Publicação de resultados

## Funcionalidades de Segurança

- **Certificados X.509** - Autenticação de eleitores
- **Threshold Cryptography** - Chave privada partilhada
- **Certificate Revocation List** - Revogação de certificados
- **Mix Network** - Anonimização de votos
- **Logging Auditável** - Rastreabilidade de operações
