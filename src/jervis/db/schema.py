"""Tabelas do banco (MySQL 8, InnoDB, utf8mb4), criadas na inicialização se não existirem.

- customers: clientes atendidos (nome e id no Desk Manager).
- service: plataformas consultadas e suas configurações (url, slug, identificador da classe do coletor) e a
  chave MFA da conta de parceiro, criptografada (usuário e senha ficam no cofre, pelo slug).
- customer_services: liga um cliente a um serviço, com o nome do cliente dentro da plataforma; a chave MFA
  aqui é opcional (cliente com conta própria) e, quando existe, tem prioridade sobre a do serviço.

A ordem da lista é a de criação: tabelas referenciadas por chave estrangeira vêm antes.
"""

from __future__ import annotations

_TABLE_OPTIONS = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci"
_TIMESTAMPS = """
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"""

TABLES: list[tuple[str, str]] = [
    ("customers", f"""
CREATE TABLE IF NOT EXISTS customers (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL COMMENT 'nome do cliente',
  desk_manager_id VARCHAR(64) NULL COMMENT 'id do cliente no Desk Manager',{_TIMESTAMPS},
  PRIMARY KEY (id),
  UNIQUE KEY uq_customers_desk_manager_id (desk_manager_id)
) {_TABLE_OPTIONS} COMMENT='clientes atendidos'"""),

    ("service", f"""
CREATE TABLE IF NOT EXISTS service (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  slug VARCHAR(64) NOT NULL COMMENT 'identificador curto (ex.: acronis)',
  url VARCHAR(512) NOT NULL COMMENT 'endereço de acesso da plataforma',
  class_identifier VARCHAR(255) NOT NULL COMMENT 'classe do coletor (ex.: acronis ou jervis.collectors.acronis.AcronisCollector)',
  settings JSON NULL COMMENT 'demais configurações (MFA, tempos limite, seletores, parâmetros da coleta)',
  mfa_secret_encrypted VARCHAR(1024) CHARACTER SET ascii NULL COMMENT 'chave MFA (TOTP) da conta de parceiro, criptografada com Fernet',{_TIMESTAMPS},
  PRIMARY KEY (id),
  UNIQUE KEY uq_service_slug (slug)
) {_TABLE_OPTIONS} COMMENT='plataformas consultadas e suas configurações'"""),

    ("customer_services", f"""
CREATE TABLE IF NOT EXISTS customer_services (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  customer_id INT UNSIGNED NOT NULL,
  service_id INT UNSIGNED NOT NULL,
  external_name VARCHAR(255) NULL COMMENT 'nome ou identificador do cliente na plataforma (vazio = customers.name)',
  products VARCHAR(512) NULL COMMENT 'produtos contratados nesse serviço (ex.: Acronis EDR Security; Acronis Advanced Management)',
  contracted_devices INT UNSIGNED NULL COMMENT 'dispositivos contratados',
  mfa_secret_encrypted VARCHAR(1024) CHARACTER SET ascii NULL
    COMMENT 'chave MFA (TOTP) própria do cliente, criptografada com Fernet; vazio = a do serviço',{_TIMESTAMPS},
  PRIMARY KEY (id),
  UNIQUE KEY uq_customer_services (customer_id, service_id),
  KEY ix_customer_services_service (service_id),
  CONSTRAINT fk_customer_services_customer FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE CASCADE,
  CONSTRAINT fk_customer_services_service FOREIGN KEY (service_id) REFERENCES service (id) ON DELETE RESTRICT
) {_TABLE_OPTIONS} COMMENT='serviços contratados por cliente'"""),
]

TABLE_NAMES = [name for name, _ in TABLES]

# Colunas incluídas depois da primeira versão: bancos criados antes recebem com ALTER TABLE (nada é apagado).
# (tabela, coluna, definição com a posição)
ADDED_COLUMNS: list[tuple[str, str, str]] = [
    ("service", "mfa_secret_encrypted", "mfa_secret_encrypted VARCHAR(1024) CHARACTER SET ascii NULL COMMENT 'chave MFA (TOTP) da conta de parceiro, criptografada com Fernet' AFTER settings"),
    ("customer_services", "external_name", "external_name VARCHAR(255) NULL COMMENT 'nome ou identificador do cliente na plataforma (vazio = customers.name)' AFTER service_id"),
    ("customer_services", "products", "products VARCHAR(512) NULL COMMENT 'produtos contratados nesse serviço (ex.: Acronis EDR Security; Acronis Advanced Management)' AFTER external_name"),
    ("customer_services", "contracted_devices", "contracted_devices INT UNSIGNED NULL COMMENT 'dispositivos contratados' AFTER products"),
]
