"""Leanttro CRM — Flask + SQLAlchemy, um arquivo só.

Dev:   python app.py                (HOST/PORT/DEBUG por env)
Prod:  gunicorn app:app             (docker-entrypoint.sh roda `python app.py init-db` antes)
CLI:   python app.py init-db
Banco: SQLite em DATA_DIR/db.sqlite (Docker: volume /data). DATABASE_URL só se quiser Postgres.
Dinheiro: sempre em CENTAVOS (inteiro). Percentuais: float (40.0 = 40%).
"""
import base64
import calendar
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from functools import lru_cache, wraps
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, abort, g, jsonify, redirect, render_template, request, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, UniqueConstraint, delete, event, func, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# ═══════════════════════════════════════════════════════════════════════════
# CONFIG / ENV
# ═══════════════════════════════════════════════════════════════════════════
def _env(nome, padrao=""):
    return os.environ.get(nome, padrao).strip()


def _int(nome, padrao):
    try:
        return int(_env(nome) or padrao)
    except ValueError:
        return padrao


DEBUG = _env("DEBUG") == "1"
DATA_DIR = Path(_env("DATA_DIR") or (BASE_DIR / "data")).resolve()
TZ = ZoneInfo(_env("TZ_NAME") or "America/Sao_Paulo")
SCHEMA_VERSAO = 1
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _segredo(nome):
    """Env tem prioridade. Sem env, gera e guarda em DATA_DIR/.<nome> (sobrevive a reinício do container)."""
    v = _env(nome)
    if v:
        return v
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    arq = DATA_DIR / f".{nome.lower()}"
    if not arq.exists():
        arq.write_text(secrets.token_urlsafe(48))
        os.chmod(arq, 0o600)
    return arq.read_text().strip()


def _db_url():
    url = _env("DATABASE_URL")
    if not url:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        return "sqlite:///" + str(DATA_DIR / "db.sqlite")
    if url.startswith("postgres://"):
        return "postgresql+psycopg2://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


def agora():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hoje():
    return datetime.now(TZ).date()


db = SQLAlchemy()


@event.listens_for(Engine, "connect")
def _pragmas_sqlite(conexao, _registro):
    """SQLite: WAL, espera em vez de 'database is locked' e FKs ligadas (cascade funciona)."""
    if isinstance(conexao, sqlite3.Connection):
        cur = conexao.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=10000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


# ═══════════════════════════════════════════════════════════════════════════
# COFRE DE CHAVES (Groq / Serper de cada vendedor) — cifradas em repouso
# ═══════════════════════════════════════════════════════════════════════════
@lru_cache(maxsize=1)
def _fernet():
    chave = hashlib.sha256(_segredo("APP_KEY").encode()).digest()
    return Fernet(base64.urlsafe_b64encode(chave))


def cifrar(txt):
    return _fernet().encrypt(txt.encode()).decode() if txt else ""


def decifrar(tok):
    if not tok:
        return ""
    try:
        return _fernet().decrypt(tok.encode()).decode()
    except InvalidToken:
        return ""


def mascarar(tok):
    v = decifrar(tok)
    return ("•••• " + v[-4:]) if v else ""


# ═══════════════════════════════════════════════════════════════════════════
# MODELS
#   Acesso:     users, rate_hits, api_uso, config, schema_info
#   Prospecção: buscas, busca_resultados
#   Vendas:     servicos, leads, lead_historico, atividades, propostas, vendas, pagamentos, comissoes
#   Operação:   clientes, projetos, projeto_horas, materiais
#   Financeiro: custos
#   Gestão:     candidatos, treinamento_modulos, treinamento_progresso
# ═══════════════════════════════════════════════════════════════════════════
LEAD_STATUS = ("novo", "em_contato", "qualificado", "proposta_enviada", "negociacao", "fechado", "perdido")
PAPEIS = ("admin", "vendedor")


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("papel in ('admin','vendedor')", name="ck_users_papel"),
        CheckConstraint("status in ('ativo','bloqueado')", name="ck_users_status"),
    )
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(254), nullable=False)
    email_norm = db.Column(db.String(254), nullable=False, unique=True)
    senha_hash = db.Column(db.String(255), nullable=False)
    papel = db.Column(db.String(10), nullable=False, default="vendedor")
    status = db.Column(db.String(10), nullable=False, default="ativo", index=True)
    telefone = db.Column(db.String(30))
    # percentuais próprios (NULL = usa o global da tabela config)
    comissao_setup_pct = db.Column(db.Float)
    comissao_mensal_pct = db.Column(db.Float)
    # chaves de API do vendedor, cifradas (Fernet)
    groq_key_enc = db.Column(db.Text, nullable=False, default="")
    serper_key_enc = db.Column(db.Text, nullable=False, default="")
    trocar_senha = db.Column(db.Boolean, nullable=False, default=False)
    sessao_versao = db.Column(db.Integer, nullable=False, default=1)   # +1 derruba todas as sessões da pessoa
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)
    ultimo_login = db.Column(db.DateTime)

    @property
    def is_admin(self):
        return self.papel == "admin"


class RateHit(db.Model):
    __tablename__ = "rate_hits"
    id = db.Column(db.Integer, primary_key=True)
    chave = db.Column(db.String(160), nullable=False, index=True)
    ts = db.Column(db.Float, nullable=False)


class ApiUso(db.Model):
    """Consumo de APIs por vendedor (alimenta limites e o custo variável de APIs)."""
    __tablename__ = "api_uso"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    servico = db.Column(db.String(10), nullable=False)                 # serper | groq
    qtd = db.Column(db.Integer, nullable=False, default=1)
    ts = db.Column(db.DateTime, nullable=False, default=agora)


class Config(db.Model):
    __tablename__ = "config"
    chave = db.Column(db.String(60), primary_key=True)
    valor = db.Column(db.Text, nullable=False, default="")


class SchemaInfo(db.Model):
    __tablename__ = "schema_info"
    id = db.Column(db.Integer, primary_key=True)
    versao = db.Column(db.Integer, nullable=False, default=1)


class Busca(db.Model):
    __tablename__ = "buscas"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    consulta = db.Column(db.String(200), nullable=False)
    cidade = db.Column(db.String(120))
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)


class BuscaResultado(db.Model):
    """Resultado bruto do Serper. É 'potencial', nunca contato validado."""
    __tablename__ = "busca_resultados"
    id = db.Column(db.Integer, primary_key=True)
    busca_id = db.Column(db.Integer, db.ForeignKey("buscas.id", ondelete="CASCADE"), nullable=False, index=True)
    titulo = db.Column(db.String(200), nullable=False)
    site = db.Column(db.String(300))
    telefone = db.Column(db.String(40))
    endereco = db.Column(db.String(300))
    raw_json = db.Column(db.Text)
    status = db.Column(db.String(12), nullable=False, default="novo")  # novo | importado | descartado
    lead_id = db.Column(db.Integer, db.ForeignKey("leads.id", ondelete="SET NULL"))


class Servico(db.Model):
    __tablename__ = "servicos"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    descricao = db.Column(db.Text, nullable=False, default="")
    preco_setup_cent = db.Column(db.Integer, nullable=False, default=0)
    preco_mensal_cent = db.Column(db.Integer, nullable=False, default=0)
    ativo = db.Column(db.Boolean, nullable=False, default=True)


class Lead(db.Model):
    __tablename__ = "leads"
    __table_args__ = (CheckConstraint("status in (" + ",".join(f"'{s}'" for s in LEAD_STATUS) + ")", name="ck_leads_status"),)
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    empresa = db.Column(db.String(160), nullable=False)
    contato = db.Column(db.String(120))
    telefone = db.Column(db.String(40))
    whatsapp = db.Column(db.String(40))
    email = db.Column(db.String(254))
    site = db.Column(db.String(300))
    segmento = db.Column(db.String(80))
    cidade = db.Column(db.String(120))
    origem = db.Column(db.String(20), nullable=False, default="manual")  # serper | manual | indicacao
    servico_id = db.Column(db.Integer, db.ForeignKey("servicos.id"))
    valor_estimado_cent = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default="novo", index=True)
    proxima_atividade_em = db.Column(db.DateTime)
    motivo_perda = db.Column(db.String(200))
    dedupe_key = db.Column(db.String(300), unique=True)                 # domínio do site ou telefone (só dígitos)
    versao = db.Column(db.Integer, nullable=False, default=1)           # trava otimista
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)
    atualizado_em = db.Column(db.DateTime, nullable=False, default=agora, onupdate=agora)


class LeadHistorico(db.Model):
    __tablename__ = "lead_historico"
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey("leads.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    tipo = db.Column(db.String(12), nullable=False, default="nota")     # nota | contato | status | proposta
    texto = db.Column(db.Text, nullable=False, default="")
    status_de = db.Column(db.String(20))
    status_para = db.Column(db.String(20))
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)


class Atividade(db.Model):
    __tablename__ = "atividades"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    lead_id = db.Column(db.Integer, db.ForeignKey("leads.id", ondelete="CASCADE"))
    cliente_id = db.Column(db.Integer, db.ForeignKey("clientes.id", ondelete="CASCADE"))
    titulo = db.Column(db.String(200), nullable=False)
    vence_em = db.Column(db.DateTime)
    feita_em = db.Column(db.DateTime)


class Cliente(db.Model):
    """Nasce de um lead fechado (lead_id) ou de cadastro manual direto (origem='manual')."""
    __tablename__ = "clientes"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    lead_id = db.Column(db.Integer, db.ForeignKey("leads.id", ondelete="SET NULL"), unique=True)
    empresa = db.Column(db.String(160), nullable=False)
    contato = db.Column(db.String(120))
    documento = db.Column(db.String(20))                                # CNPJ/CPF
    telefone = db.Column(db.String(40))
    email = db.Column(db.String(254))
    site = db.Column(db.String(300))
    endereco = db.Column(db.String(300))
    origem = db.Column(db.String(10), nullable=False, default="manual")  # manual | lead
    observacoes = db.Column(db.Text, nullable=False, default="")
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)


class Proposta(db.Model):
    __tablename__ = "propostas"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    lead_id = db.Column(db.Integer, db.ForeignKey("leads.id", ondelete="SET NULL"))
    cliente_id = db.Column(db.Integer, db.ForeignKey("clientes.id", ondelete="SET NULL"))
    servico_id = db.Column(db.Integer, db.ForeignKey("servicos.id"))
    valor_setup_cent = db.Column(db.Integer, nullable=False, default=0)
    valor_mensal_cent = db.Column(db.Integer, nullable=False, default=0)
    condicoes = db.Column(db.Text, nullable=False, default="")
    validade = db.Column(db.Date)
    status = db.Column(db.String(12), nullable=False, default="rascunho")  # rascunho | enviada | aceita | recusada
    pdf_path = db.Column(db.String(300))                                # relativo a DATA_DIR
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)


class Venda(db.Model):
    __tablename__ = "vendas"
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey("leads.id", ondelete="SET NULL"))
    cliente_id = db.Column(db.Integer, db.ForeignKey("clientes.id"), nullable=False, index=True)
    vendedor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    servico_id = db.Column(db.Integer, db.ForeignKey("servicos.id"))
    proposta_id = db.Column(db.Integer, db.ForeignKey("propostas.id", ondelete="SET NULL"))
    valor_setup_cent = db.Column(db.Integer, nullable=False, default=0)
    valor_mensal_cent = db.Column(db.Integer, nullable=False, default=0)
    # percentuais GRAVADOS no fechamento (mudar a regra global depois não altera vendas antigas)
    pct_setup = db.Column(db.Float, nullable=False, default=0)
    pct_mensal = db.Column(db.Float, nullable=False, default=0)
    mensal_ativa = db.Column(db.Boolean, nullable=False, default=False)  # False = cliente cancelou a hospedagem
    mensal_inicio = db.Column(db.Date)                                   # vencimento da 1ª mensalidade
    fechada_em = db.Column(db.Date, nullable=False, default=hoje)
    versao = db.Column(db.Integer, nullable=False, default=1)
    pagamentos = db.relationship("Pagamento", backref="venda", cascade="all, delete-orphan", passive_deletes=True)


class Pagamento(db.Model):
    __tablename__ = "pagamentos"
    __table_args__ = (UniqueConstraint("venda_id", "tipo", "competencia", name="uq_pagamento_competencia"),
                      CheckConstraint("tipo in ('setup','mensalidade')", name="ck_pagamento_tipo"))
    id = db.Column(db.Integer, primary_key=True)
    venda_id = db.Column(db.Integer, db.ForeignKey("vendas.id", ondelete="CASCADE"), nullable=False, index=True)
    tipo = db.Column(db.String(12), nullable=False)
    competencia = db.Column(db.String(7), nullable=False)               # 'setup' ou 'YYYY-MM'
    valor_cent = db.Column(db.Integer, nullable=False)                  # previsto
    valor_recebido_cent = db.Column(db.Integer, nullable=False, default=0)
    vence_em = db.Column(db.Date, nullable=False)
    pago_em = db.Column(db.Date)                                        # data do último recebimento
    comissao = db.relationship("Comissao", uselist=False, backref="pagamento",
                               cascade="all, delete-orphan", passive_deletes=True)

    @property
    def status(self):
        if self.valor_recebido_cent >= self.valor_cent:
            return "pago"
        if self.valor_recebido_cent > 0:
            return "parcial"
        return "atrasado" if self.vence_em < hoje() else "pendente"


class Comissao(db.Model):
    """Uma por pagamento. Libera proporcionalmente ao que foi RECEBIDO."""
    __tablename__ = "comissoes"
    id = db.Column(db.Integer, primary_key=True)
    pagamento_id = db.Column(db.Integer, db.ForeignKey("pagamentos.id", ondelete="CASCADE"), nullable=False, unique=True)
    venda_id = db.Column(db.Integer, db.ForeignKey("vendas.id", ondelete="CASCADE"), nullable=False, index=True)
    vendedor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    pct = db.Column(db.Float, nullable=False)
    valor_previsto_cent = db.Column(db.Integer, nullable=False)
    valor_liberado_cent = db.Column(db.Integer, nullable=False, default=0)
    valor_pago_cent = db.Column(db.Integer, nullable=False, default=0)
    pago_em = db.Column(db.Date)

    @property
    def a_pagar_cent(self):
        return max(self.valor_liberado_cent - self.valor_pago_cent, 0)

    @property
    def status(self):
        if self.valor_liberado_cent == 0:
            return "aguardando"          # cliente ainda não pagou
        if self.a_pagar_cent > 0:
            return "liberada"            # tem dinheiro a repassar ao vendedor
        if self.valor_pago_cent >= self.valor_previsto_cent:
            return "paga"
        return "parcial"                 # repassado o que foi liberado; falta o cliente pagar o resto


class Projeto(db.Model):
    __tablename__ = "projetos"
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey("clientes.id", ondelete="CASCADE"), nullable=False, index=True)
    venda_id = db.Column(db.Integer, db.ForeignKey("vendas.id", ondelete="SET NULL"))
    nome = db.Column(db.String(160), nullable=False)
    status = db.Column(db.String(12), nullable=False, default="a_iniciar")  # a_iniciar | andamento | entregue
    prazo = db.Column(db.Date)
    custo_hora_cent = db.Column(db.Integer, nullable=False, default=0)
    observacoes = db.Column(db.Text, nullable=False, default="")


class ProjetoHoras(db.Model):
    __tablename__ = "projeto_horas"
    id = db.Column(db.Integer, primary_key=True)
    projeto_id = db.Column(db.Integer, db.ForeignKey("projetos.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    horas = db.Column(db.Float, nullable=False)
    data = db.Column(db.Date, nullable=False, default=hoje)
    descricao = db.Column(db.String(200))


class Material(db.Model):
    __tablename__ = "materiais"
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(160), nullable=False)
    categoria = db.Column(db.String(60), nullable=False, default="geral")
    arquivo = db.Column(db.String(300))                                 # relativo a DATA_DIR/uploads
    link = db.Column(db.String(500))


class Custo(db.Model):
    __tablename__ = "custos"
    __table_args__ = (CheckConstraint("tipo in ('fixo','variavel')", name="ck_custos_tipo"),
                      CheckConstraint("recorrencia in ('mensal','anual','unica')", name="ck_custos_rec"))
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(10), nullable=False)
    categoria = db.Column(db.String(60), nullable=False)
    descricao = db.Column(db.String(200), nullable=False, default="")
    valor_cent = db.Column(db.Integer, nullable=False)
    recorrencia = db.Column(db.String(10), nullable=False, default="unica")
    data = db.Column(db.Date, nullable=False, default=hoje)
    projeto_id = db.Column(db.Integer, db.ForeignKey("projetos.id", ondelete="SET NULL"))


class Candidato(db.Model):
    __tablename__ = "candidatos"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(254))
    telefone = db.Column(db.String(40))
    etapa = db.Column(db.String(20), nullable=False, default="novo")
    notas = db.Column(db.Text, nullable=False, default="")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"))  # preenchido na aprovação
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)


class TreinamentoModulo(db.Model):
    __tablename__ = "treinamento_modulos"
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(160), nullable=False)
    ordem = db.Column(db.Integer, nullable=False, default=0)
    conteudo = db.Column(db.Text, nullable=False, default="")


class TreinamentoProgresso(db.Model):
    __tablename__ = "treinamento_progresso"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    modulo_id = db.Column(db.Integer, db.ForeignKey("treinamento_modulos.id", ondelete="CASCADE"), primary_key=True)
    concluido_em = db.Column(db.DateTime, nullable=False, default=agora)


# ═══════════════════════════════════════════════════════════════════════════
# MIGRAÇÃO SIMPLES (sem Alembic)
# ═══════════════════════════════════════════════════════════════════════════
def _add_col(tabela, coluna, ddl):
    """ALTER TABLE ADD COLUMN só se a coluna ainda não existe."""
    cols = {c["name"] for c in inspect(db.engine).get_columns(tabela)}
    if coluna not in cols:
        db.session.execute(text(f"ALTER TABLE {tabela} ADD COLUMN {coluna} {ddl}"))
        db.session.commit()


# ═══════════════════════════════════════════════════════════════════════════
# REGRAS DE NEGÓCIO: percentuais, vendas, pagamentos, comissões
# ═══════════════════════════════════════════════════════════════════════════
CONFIG_PADRAO = {"comissao_setup_pct": "40", "comissao_mensal_pct": "20"}


def cfg_get(chave, padrao=""):
    c = db.session.get(Config, chave)
    return c.valor if c else CONFIG_PADRAO.get(chave, padrao)


def cfg_set(chave, valor):
    c = db.session.get(Config, chave)
    if c:
        c.valor = str(valor)
    else:
        db.session.add(Config(chave=chave, valor=str(valor)))


def pct_efetivo(vendedor, tipo):
    """Ordem: (venda, tratada na criação) > vendedor > global."""
    campo = "comissao_setup_pct" if tipo == "setup" else "comissao_mensal_pct"
    v = getattr(vendedor, campo)
    return float(v) if v is not None else float(cfg_get(campo, "0"))


def _add_meses(d, n):
    m = d.month - 1 + n
    y, m = d.year + m // 12, m % 12 + 1
    return date(y, m, min(d.day, calendar.monthrange(y, m)[1]))


def _novo_pagamento(venda, tipo, competencia, valor_cent, vence):
    p = Pagamento(venda_id=venda.id, tipo=tipo, competencia=competencia, valor_cent=valor_cent, vence_em=vence)
    db.session.add(p)
    db.session.flush()
    pct = venda.pct_setup if tipo == "setup" else venda.pct_mensal
    db.session.add(Comissao(pagamento_id=p.id, venda_id=venda.id, vendedor_id=venda.vendedor_id,
                            pct=pct, valor_previsto_cent=round(valor_cent * pct / 100)))
    return p


def manter_mensalidades(venda, meses=12):
    """Mantém criadas as mensalidades dos próximos `meses`. Idempotente. Só enquanto mensal_ativa."""
    if not venda.mensal_ativa or venda.valor_mensal_cent <= 0 or not venda.mensal_inicio:
        return 0
    existentes = set(db.session.scalars(select(Pagamento.competencia).where(
        Pagamento.venda_id == venda.id, Pagamento.tipo == "mensalidade")))
    limite, k, criados = _add_meses(hoje(), meses), 0, 0
    while True:
        venc = _add_meses(venda.mensal_inicio, k)
        if venc > limite:
            break
        comp = venc.strftime("%Y-%m")
        if comp not in existentes:
            _novo_pagamento(venda, "mensalidade", comp, venda.valor_mensal_cent, venc)
            criados += 1
        k += 1
    return criados


def manter_mensalidades_todas():
    n = 0
    for v in db.session.scalars(select(Venda).where(Venda.mensal_ativa.is_(True))):
        n += manter_mensalidades(v)
    db.session.commit()
    return n


def criar_venda(cliente, vendedor, setup_cent=0, mensal_cent=0, servico_id=None, lead=None, proposta_id=None,
                fechada_em=None, setup_vence=None, mensal_inicio=None, pct_setup=None, pct_mensal=None):
    """Fechamento numa transação só: venda + pagamentos + comissões + projeto. O caller dá commit."""
    fechada_em = fechada_em or hoje()
    venda = Venda(
        lead_id=lead.id if lead else None, cliente_id=cliente.id, vendedor_id=vendedor.id,
        servico_id=servico_id, proposta_id=proposta_id,
        valor_setup_cent=setup_cent, valor_mensal_cent=mensal_cent,
        pct_setup=pct_setup if pct_setup is not None else pct_efetivo(vendedor, "setup"),
        pct_mensal=pct_mensal if pct_mensal is not None else pct_efetivo(vendedor, "mensal"),
        mensal_ativa=mensal_cent > 0, fechada_em=fechada_em,
        mensal_inicio=(mensal_inicio or _add_meses(fechada_em, 1)) if mensal_cent > 0 else None)
    db.session.add(venda)
    db.session.flush()
    if setup_cent > 0:
        _novo_pagamento(venda, "setup", "setup", setup_cent, setup_vence or fechada_em)
    manter_mensalidades(venda)
    srv = db.session.get(Servico, servico_id) if servico_id else None
    db.session.add(Projeto(cliente_id=cliente.id, venda_id=venda.id,
                           nome=f"{srv.nome if srv else 'Projeto'} — {cliente.empresa}"[:160]))
    if lead:
        antigo, lead.status = lead.status, "fechado"
        db.session.add(LeadHistorico(lead_id=lead.id, user_id=vendedor.id, tipo="status",
                                     texto="Venda fechada", status_de=antigo, status_para="fechado"))
    return venda


def receber_pagamento(pag, total_recebido_cent, data=None):
    """Define o TOTAL recebido do pagamento (aceita parcial) e recalcula a comissão liberada."""
    total = max(0, min(int(total_recebido_cent), pag.valor_cent))
    pag.valor_recebido_cent = total
    pag.pago_em = (data or hoje()) if total > 0 else None
    c = pag.comissao
    if c:
        c.valor_liberado_cent = round(total * c.pct / 100)
    return pag


def pagar_comissao(com, valor_cent=None):
    """Repassa ao vendedor. Padrão: tudo que está liberado e ainda não foi pago."""
    a_pagar = com.a_pagar_cent
    v = a_pagar if valor_cent is None else max(0, min(int(valor_cent), a_pagar))
    if v > 0:
        com.valor_pago_cent += v
        com.pago_em = hoje()
    return v


def cancelar_mensalidade(venda):
    """Cliente não quer mais manter a hospedagem: para de gerar e remove só as futuras sem recebimento.
    Mensalidades vencidas ou já recebidas ficam (e suas comissões também)."""
    venda.mensal_ativa = False
    n = 0
    for p in list(venda.pagamentos):
        if p.tipo == "mensalidade" and p.valor_recebido_cent == 0 and p.vence_em > hoje():
            db.session.delete(p)
            n += 1
    return n


def cliente_de_lead(lead):
    c = db.session.scalar(select(Cliente).where(Cliente.lead_id == lead.id))
    if c:
        return c
    c = Cliente(owner_id=lead.owner_id, lead_id=lead.id, empresa=lead.empresa, contato=lead.contato,
                telefone=lead.telefone, email=lead.email, site=lead.site, origem="lead")
    db.session.add(c)
    db.session.flush()
    return c


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS: validação, dedupe, Serper, Groq, PDF de proposta
# ═══════════════════════════════════════════════════════════════════════════
LEAD_ORIGENS = ("serper", "manual", "indicacao")
EXT_PERMITIDAS = {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".zip", ".mp4"}


def _txt(d, campo, maximo, obrigatorio=False, nome=None):
    v = d.get(campo)
    if v is None or (isinstance(v, str) and not v.strip()):
        if obrigatorio:
            raise ValueError(f"{nome or campo} é obrigatório.")
        return None
    if not isinstance(v, str):
        raise ValueError(f"{nome or campo} inválido.")
    v = v.strip()
    if len(v) > maximo:
        raise ValueError(f"{nome or campo} passa de {maximo} caracteres.")
    return v


def dedupe_key(site, telefone):
    s = (site or "").strip().lower()
    if s:
        s = re.sub(r"^[a-z]+://", "", s)
        s = s.split("/")[0].split("?")[0].split("#")[0]
        s = re.sub(r"^www\.", "", s)
        if "." in s:
            return s[:300]
    dig = re.sub(r"\D", "", telefone or "")
    if dig.startswith("55") and len(dig) > 11:
        dig = dig[2:]
    return dig if len(dig) >= 8 else None


def _http_json(url, payload, headers, timeout=20):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise RuntimeError("Chave de API recusada. Confira em Perfil.")
        if e.code == 429:
            raise RuntimeError("Limite do provedor atingido. Tente mais tarde.")
        raise RuntimeError(f"O provedor respondeu erro {e.code}.")
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise RuntimeError("Não consegui falar com o provedor. Tente de novo.")


def serper_places(chave, consulta, cidade=""):
    q = f"{consulta} {cidade}".strip()
    data = _http_json("https://google.serper.dev/places", {"q": q, "gl": "br", "hl": "pt-br"}, {"X-API-KEY": chave})
    return data.get("places") or []


def groq_texto(chave, prompt, system):
    data = _http_json("https://api.groq.com/openai/v1/chat/completions",
                      {"model": "llama-3.3-70b-versatile", "temperature": 0.6, "max_tokens": 400,
                       "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]},
                      {"Authorization": f"Bearer {chave}"})
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError):
        raise RuntimeError("Resposta inesperada da IA.")


def _brl(cent):
    return "R$ " + f"{cent / 100:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def gerar_pdf_proposta(p, empresa, servico_nome, vendedor):
    """Gera o PDF em DATA_DIR/propostas e devolve o caminho relativo."""
    pasta = DATA_DIR / "propostas"
    pasta.mkdir(parents=True, exist_ok=True)
    rel = f"propostas/proposta_{p.id}.pdf"
    linhas = [("Proposta Comercial", 20), (f"Leanttro Tecnologia · Proposta #{p.id}", 10), ("", 10),
              (f"Para: {empresa}", 13), (f"Serviço: {servico_nome or 'Sob medida'}", 12),
              (f"Setup (pagamento único): {_brl(p.valor_setup_cent)}", 12),
              (f"Mensalidade: {_brl(p.valor_mensal_cent)}", 12),
              (f"Validade: {p.validade.strftime('%d/%m/%Y') if p.validade else 'a combinar'}", 12), ("", 10),
              ("Condições:", 12)] + [(t, 11) for t in (p.condicoes or "A combinar.").splitlines()] + \
             [("", 10), (f"Responsável: {vendedor.nome} · {vendedor.email}", 11)]
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        c = canvas.Canvas(str(DATA_DIR / rel), pagesize=A4)
        y = 800
        for t, tam in linhas:
            c.setFont("Helvetica-Bold" if tam >= 13 else "Helvetica", tam)
            c.drawString(56, y, t[:95])
            y -= tam + 9
        c.save()
    except ImportError:  # fallback sem dependência (texto simples, Latin-1)
        def esc_(s):
            return s.encode("latin-1", "replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        y, cont = 800, []
        for t, tam in linhas:
            cont.append(f"BT /F1 {tam} Tf 56 {y} Td ({esc_(t[:95])}) Tj ET")
            y -= tam + 9
        stream = "\n".join(cont).encode("latin-1")
        objs = [b"<</Type/Catalog/Pages 2 0 R>>", b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
                b"<</Length %d>>\nstream\n" % len(stream) + stream + b"\nendstream",
                b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>"]
        out, offs = b"%PDF-1.4\n", []
        for i, o in enumerate(objs, 1):
            offs.append(len(out))
            out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
        x = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offs)
        out += b"trailer<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF" % (len(objs) + 1, x)
        (DATA_DIR / rel).write_bytes(out)
    return rel


# ═══════════════════════════════════════════════════════════════════════════
# APP
# ═══════════════════════════════════════════════════════════════════════════
def _norm(email):
    return (email or "").strip().lower()


def _centavos(v, nome):
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ValueError(f"{nome} inválido.")
    return v


def _pct(v):
    if v is None or v == "":
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= 100:
        raise ValueError("Percentual deve estar entre 0 e 100.")
    return float(v)


def _data(v):
    try:
        return date.fromisoformat(v) if v else None
    except (TypeError, ValueError):
        raise ValueError("Data inválida (use AAAA-MM-DD).")


def limitar(chave, maximo, janela_s):
    """Rate limit simples no banco. True = pode seguir."""
    agora_ts = time.time()
    db.session.execute(delete(RateHit).where(RateHit.chave == chave, RateHit.ts < agora_ts - janela_s))
    n = db.session.scalar(select(func.count()).select_from(RateHit).where(RateHit.chave == chave)) or 0
    if n >= maximo:
        db.session.commit()
        return False
    db.session.add(RateHit(chave=chave, ts=agora_ts))
    db.session.commit()
    return True


def usuario_atual():
    if "_u" in g:
        return g._u
    u, uid = None, session.get("uid")
    if uid:
        u = db.session.get(User, uid)
        if not u or u.status != "ativo" or u.sessao_versao != session.get("sv"):
            u = None
            session.pop("uid", None)
    g._u = u
    return u


def escopo(stmt, coluna, equipe=False):
    """Isolamento no BACKEND: vendedor só vê o que é dele. Admin vê o próprio por padrão
    (perfil único = também vendedor); passa equipe=True para ver todos."""
    u = usuario_atual()
    if u.is_admin and equipe:
        return stmt
    return stmt.where(coluna == u.id)


def registrar_uso(user, servico, qtd=1):
    db.session.add(ApiUso(user_id=user.id, servico=servico, qtd=qtd))


def chave_do_vendedor(user, servico):
    """Devolve a chave em texto puro (uso interno ao chamar Groq/Serper). Nunca mandar ao front."""
    return decifrar(user.groq_key_enc if servico == "groq" else user.serper_key_enc)


def _user_json(u):
    return dict(id=u.id, nome=u.nome, email=u.email, papel=u.papel, status=u.status, telefone=u.telefone,
                comissao_setup_pct=u.comissao_setup_pct, comissao_mensal_pct=u.comissao_mensal_pct,
                groq=mascarar(u.groq_key_enc), serper=mascarar(u.serper_key_enc),
                ultimo_login=u.ultimo_login.isoformat() if u.ultimo_login else None)


def _com_json(c):
    return dict(id=c.id, pagamento_id=c.pagamento_id, venda_id=c.venda_id, vendedor_id=c.vendedor_id, pct=c.pct,
                previsto_cent=c.valor_previsto_cent, liberado_cent=c.valor_liberado_cent,
                pago_cent=c.valor_pago_cent, a_pagar_cent=c.a_pagar_cent, status=c.status)


def _aplicar_chaves(u, d):
    """None/ausente = mantém; '' = remove; texto = substitui."""
    for campo, col in (("groq", "groq_key_enc"), ("serper", "serper_key_enc")):
        v = d.get(campo)
        if v is None:
            continue
        if not isinstance(v, str) or len(v) > 300:
            raise ValueError("Chave inválida.")
        setattr(u, col, cifrar(v.strip()))


def criar_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=_segredo("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=_db_url(),
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_env("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
        MAX_CONTENT_LENGTH=_int("MAX_UPLOAD_MB", 10) * 1024 * 1024,
    )
    app.json.ensure_ascii = False
    if _env("TRUST_PROXY") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    db.init_app(app)

    @app.template_filter("reais")
    def _reais(c):
        s = f"{(c or 0) / 100:,.2f}"
        return "R$ " + s.replace(",", "X").replace(".", ",").replace("X", ".")

    @app.context_processor
    def _ctx():
        return dict(csrf=session.get("csrf", ""), usuario=usuario_atual(), app_nome="Leanttro CRM")

    @app.before_request
    def _csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            enviado = request.headers.get("X-CSRF") or request.form.get("csrf", "")
            if not hmac.compare_digest(enviado, session["csrf"]):
                if request.path.startswith("/api/"):
                    return jsonify(ok=False, erro="Sessão expirada. Recarregue a página."), 400
                return render_template("login.html", erro="Sua sessão expirou. Tente entrar de novo."), 400

    @app.after_request
    def _headers(r):
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["X-Frame-Options"] = "DENY"
        r.headers["Referrer-Policy"] = "same-origin"
        r.headers["Content-Security-Policy"] = ("default-src 'self' 'unsafe-inline' data: blob:; "
                                                "connect-src 'self'; frame-ancestors 'none'")
        if request.path.startswith(("/api/", "/app", "/login", "/conta")):
            r.headers["Cache-Control"] = "no-store"
        return r

    def login_obrigatorio(f):
        @wraps(f)
        def w(*a, **k):
            u = usuario_atual()
            if not u:
                if request.path.startswith("/api/"):
                    return jsonify(ok=False, erro="Faça login."), 401
                return redirect("/login")
            if u.trocar_senha and request.endpoint not in ("senha", "sair"):
                if request.path.startswith("/api/"):
                    return jsonify(ok=False, erro="Troque a senha provisória primeiro."), 403
                return redirect("/conta/senha")
            return f(*a, **k)
        return w

    def admin_obrigatorio(f):
        @wraps(f)
        @login_obrigatorio
        def w(*a, **k):
            if not usuario_atual().is_admin:
                return jsonify(ok=False, erro="Acesso restrito ao administrador."), 403
            return f(*a, **k)
        return w

    def _json():
        d = request.get_json(silent=True)
        return d if isinstance(d, dict) else {}

    def _erro(msg, cod=400):
        return jsonify(ok=False, erro=msg), cod

    # ── básicas ─────────────────────────────────────────────────────────────
    @app.get("/healthz")
    def healthz():
        db.session.execute(text("SELECT 1"))
        return "ok"

    @app.get("/")
    def raiz():
        return redirect("/app" if usuario_atual() else "/login")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html", erro=None)
        email, senha = _norm(request.form.get("email")), request.form.get("senha", "")
        if not limitar(f"login:{request.remote_addr}:{email}", 8, 600):
            return render_template("login.html", erro="Muitas tentativas. Aguarde alguns minutos."), 429
        u = db.session.scalar(select(User).where(User.email_norm == email))
        if not u or not check_password_hash(u.senha_hash, senha):
            return render_template("login.html", erro="E-mail ou senha incorretos."), 401
        if u.status != "ativo":
            return render_template("login.html", erro="Acesso desativado. Fale com o administrador."), 403
        session.clear()
        session.permanent = True
        session.update(uid=u.id, sv=u.sessao_versao, csrf=secrets.token_urlsafe(24))
        u.ultimo_login = agora()
        if u.is_admin:
            manter_mensalidades_todas()
        db.session.commit()
        return redirect("/conta/senha" if u.trocar_senha else "/app")

    @app.post("/sair")
    def sair():
        session.clear()
        return redirect("/login")

    @app.get("/app")
    @login_obrigatorio
    def painel():
        return render_template("app.html")

    @app.route("/conta/senha", methods=["GET", "POST"])
    @login_obrigatorio
    def senha():
        u = usuario_atual()
        if request.method == "GET":
            return render_template("senha.html", erro=None)
        atual, nova = request.form.get("atual", ""), request.form.get("nova", "")
        if not check_password_hash(u.senha_hash, atual):
            return render_template("senha.html", erro="Senha atual incorreta."), 400
        if len(nova) < 8:
            return render_template("senha.html", erro="A nova senha precisa ter ao menos 8 caracteres."), 400
        u.senha_hash = generate_password_hash(nova)
        u.trocar_senha = False
        u.sessao_versao += 1                     # derruba as outras sessões
        db.session.commit()
        session["sv"] = u.sessao_versao
        return redirect("/app")

    # ── minhas chaves (vendedor altera as próprias) ────────────────────────
    @app.get("/api/me")
    @login_obrigatorio
    def api_me():
        return jsonify(ok=True, usuario=_user_json(usuario_atual()))

    @app.put("/api/me/chaves")
    @login_obrigatorio
    def api_me_chaves():
        try:
            _aplicar_chaves(usuario_atual(), _json())
        except ValueError as e:
            return _erro(str(e))
        db.session.commit()
        return jsonify(ok=True, usuario=_user_json(usuario_atual()))

    # ── admin: usuários e configuração ─────────────────────────────────────
    @app.get("/api/admin/usuarios")
    @admin_obrigatorio
    def admin_usuarios():
        return jsonify(ok=True, usuarios=[_user_json(u) for u in db.session.scalars(select(User).order_by(User.nome))])

    @app.post("/api/admin/usuarios")
    @admin_obrigatorio
    def admin_criar_usuario():
        d = _json()
        nome, email = (d.get("nome") or "").strip()[:80], _norm(d.get("email"))
        papel = d.get("papel", "vendedor")
        if not nome or not EMAIL_RE.match(email) or papel not in PAPEIS:
            return _erro("Informe nome, e-mail válido e papel (admin ou vendedor).")
        temp = secrets.token_urlsafe(9)
        try:
            u = User(nome=nome, email=email, email_norm=email, papel=papel, telefone=(d.get("telefone") or "")[:30] or None,
                     comissao_setup_pct=_pct(d.get("comissao_setup_pct")),
                     comissao_mensal_pct=_pct(d.get("comissao_mensal_pct")),
                     senha_hash=generate_password_hash(temp), trocar_senha=True)
            _aplicar_chaves(u, d)
            db.session.add(u)
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        except IntegrityError:
            db.session.rollback()
            return _erro("Já existe um usuário com esse e-mail.", 409)
        return jsonify(ok=True, usuario=_user_json(u), senha_temporaria=temp)   # só aparece desta vez

    @app.put("/api/admin/usuarios/<int:uid>")
    @admin_obrigatorio
    def admin_editar_usuario(uid):
        u, d = db.session.get(User, uid), _json()
        if not u:
            abort(404)
        eu = usuario_atual()
        if u.id == eu.id and (d.get("status") == "bloqueado" or d.get("papel") == "vendedor"):
            return _erro("Você não pode bloquear nem rebaixar o próprio acesso.")
        try:
            if "nome" in d and (d["nome"] or "").strip():
                u.nome = d["nome"].strip()[:80]
            if "telefone" in d:
                u.telefone = (d["telefone"] or "")[:30] or None
            if d.get("papel") in PAPEIS:
                u.papel = d["papel"]
            if d.get("status") in ("ativo", "bloqueado"):
                u.status = d["status"]
                if u.status == "bloqueado":
                    u.sessao_versao += 1
            for campo in ("comissao_setup_pct", "comissao_mensal_pct"):
                if campo in d:                      # null = volta a usar o global
                    setattr(u, campo, _pct(d[campo]))
            _aplicar_chaves(u, d)
            temp = None
            if d.get("resetar_senha"):
                temp = secrets.token_urlsafe(9)
                u.senha_hash, u.trocar_senha = generate_password_hash(temp), True
                u.sessao_versao += 1
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        db.session.commit()
        return jsonify(ok=True, usuario=_user_json(u), senha_temporaria=temp)

    @app.get("/api/admin/config")
    @admin_obrigatorio
    def admin_config_get():
        return jsonify(ok=True, config={k: float(cfg_get(k)) for k in CONFIG_PADRAO})

    @app.put("/api/admin/config")
    @admin_obrigatorio
    def admin_config_put():
        d = _json()
        try:
            for k in CONFIG_PADRAO:
                if k in d:
                    p = _pct(d[k])
                    if p is None:
                        raise ValueError("Percentual obrigatório.")
                    cfg_set(k, p)
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        db.session.commit()
        return jsonify(ok=True, config={k: float(cfg_get(k)) for k in CONFIG_PADRAO})

    # ── admin: dinheiro (recebimento, comissão, cancelamento) ──────────────
    @app.post("/api/admin/pagamentos/<int:pid>/receber")
    @admin_obrigatorio
    def admin_receber(pid):
        p, d = db.session.get(Pagamento, pid), _json()
        if not p:
            abort(404)
        try:
            receber_pagamento(p, _centavos(d.get("valor_recebido_cent"), "Valor"), _data(d.get("data")))
        except ValueError as e:
            return _erro(str(e))
        db.session.commit()
        return jsonify(ok=True, status=p.status, comissao=_com_json(p.comissao))

    @app.post("/api/admin/comissoes/<int:cid>/pagar")
    @admin_obrigatorio
    def admin_pagar_comissao(cid):
        c, d = db.session.get(Comissao, cid), _json()
        if not c:
            abort(404)
        try:
            v = pagar_comissao(c, _centavos(d["valor_cent"], "Valor") if d.get("valor_cent") is not None else None)
        except ValueError as e:
            return _erro(str(e))
        db.session.commit()
        return jsonify(ok=True, pago_agora_cent=v, comissao=_com_json(c))

    @app.post("/api/admin/vendas/<int:vid>/cancelar-mensal")
    @admin_obrigatorio
    def admin_cancelar_mensal(vid):
        v = db.session.get(Venda, vid)
        if not v:
            abort(404)
        removidas = cancelar_mensalidade(v)
        db.session.commit()
        return jsonify(ok=True, mensalidades_removidas=removidas)

    @app.get("/api/comissoes")
    @login_obrigatorio
    def api_comissoes():
        if limitar("manter_mensalidades", 1, 3600):
            manter_mensalidades_todas()
        stmt = escopo(select(Comissao), Comissao.vendedor_id, equipe=request.args.get("equipe") == "1")
        rows = list(db.session.scalars(stmt.order_by(Comissao.id.desc()).limit(500)))
        tot = dict(previsto_cent=sum(c.valor_previsto_cent for c in rows),
                   liberado_cent=sum(c.valor_liberado_cent for c in rows),
                   pago_cent=sum(c.valor_pago_cent for c in rows),
                   a_pagar_cent=sum(c.a_pagar_cent for c in rows))
        return jsonify(ok=True, totais=tot, comissoes=[_com_json(c) for c in rows])

    # ═══════════════════════════════════════════════════════════════════════
    # ROTAS NOVAS
    # ═══════════════════════════════════════════════════════════════════════
    def _fmt(dt):
        return dt.isoformat() if dt else None

    def _lead_meu(lid):
        l, u = db.session.get(Lead, lid), usuario_atual()
        if not l or (l.owner_id != u.id and not u.is_admin):
            abort(404)
        return l

    def _lead_json(l):
        return dict(id=l.id, owner_id=l.owner_id, empresa=l.empresa, contato=l.contato, telefone=l.telefone,
                    whatsapp=l.whatsapp, email=l.email, site=l.site, segmento=l.segmento, cidade=l.cidade,
                    origem=l.origem, servico_id=l.servico_id, valor_estimado_cent=l.valor_estimado_cent,
                    status=l.status, motivo_perda=l.motivo_perda, versao=l.versao,
                    proxima_atividade_em=_fmt(l.proxima_atividade_em), atualizado_em=_fmt(l.atualizado_em))

    def _preencher_lead(l, d, novo=False):
        l.empresa = _txt(d, "empresa", 160, novo or "empresa" in d, "Empresa") or l.empresa
        for campo, n in (("contato", 120), ("telefone", 40), ("whatsapp", 40), ("segmento", 80), ("cidade", 120), ("site", 300)):
            if campo in d:
                setattr(l, campo, _txt(d, campo, n))
        if "email" in d:
            e = _txt(d, "email", 254)
            if e and not EMAIL_RE.match(e):
                raise ValueError("E-mail inválido.")
            l.email = e
        if "valor_estimado_cent" in d:
            l.valor_estimado_cent = _centavos(d["valor_estimado_cent"], "Valor estimado")
        if "servico_id" in d:
            sid = d["servico_id"]
            if sid is not None and not db.session.get(Servico, sid):
                raise ValueError("Serviço inexistente.")
            l.servico_id = sid
        if "origem" in d and d["origem"] in LEAD_ORIGENS:
            l.origem = d["origem"]
        if "proxima_atividade_em" in d:
            try:
                l.proxima_atividade_em = datetime.fromisoformat(d["proxima_atividade_em"]) if d["proxima_atividade_em"] else None
            except (TypeError, ValueError):
                raise ValueError("Data da próxima atividade inválida.")
        chave = dedupe_key(l.site, l.telefone)
        if chave != l.dedupe_key:
            outro = db.session.scalar(select(Lead.id).where(Lead.dedupe_key == chave)) if chave else None
            if outro and outro != l.id:
                raise ValueError("Já existe um lead com esse site ou telefone.")
            l.dedupe_key = chave

    # ── leads ──────────────────────────────────────────────────────────────
    @app.get("/api/leads")
    @login_obrigatorio
    def api_leads():
        stmt = escopo(select(Lead), Lead.owner_id, equipe=request.args.get("equipe") == "1")
        rows = db.session.scalars(stmt.order_by(Lead.atualizado_em.desc()).limit(300))
        return jsonify(ok=True, leads=[_lead_json(l) for l in rows])

    @app.post("/api/leads")
    @login_obrigatorio
    def api_lead_criar():
        d, u = _json(), usuario_atual()
        l = Lead(owner_id=u.id, empresa="")
        try:
            _preencher_lead(l, d, novo=True)
            db.session.add(l)
            db.session.flush()
            db.session.add(LeadHistorico(lead_id=l.id, user_id=u.id, tipo="nota", texto="Lead criado"))
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e), 409 if "Já existe" in str(e) else 400)
        except IntegrityError:
            db.session.rollback()
            return _erro("Já existe um lead com esse site ou telefone.", 409)
        return jsonify(ok=True, lead=_lead_json(l))

    @app.get("/api/leads/<int:lid>")
    @login_obrigatorio
    def api_lead_ver(lid):
        l = _lead_meu(lid)
        hist = db.session.scalars(select(LeadHistorico).where(LeadHistorico.lead_id == l.id)
                                  .order_by(LeadHistorico.id.desc()).limit(50))
        props = db.session.scalars(select(Proposta).where(Proposta.lead_id == l.id).order_by(Proposta.id.desc()))
        return jsonify(ok=True, lead=_lead_json(l),
                       historico=[dict(tipo=h.tipo, texto=h.texto, de=h.status_de, para=h.status_para, em=_fmt(h.criado_em)) for h in hist],
                       propostas=[dict(id=p.id, status=p.status, setup_cent=p.valor_setup_cent, mensal_cent=p.valor_mensal_cent,
                                       tem_pdf=bool(p.pdf_path)) for p in props])

    @app.put("/api/leads/<int:lid>")
    @login_obrigatorio
    def api_lead_editar(lid):
        l, d, u = _lead_meu(lid), _json(), usuario_atual()
        if "versao" in d and d["versao"] != l.versao:
            return _erro("Este lead foi alterado por outra pessoa. Recarregue.", 409)
        try:
            antigo = l.status
            _preencher_lead(l, d)
            novo = d.get("status")
            if novo and novo != antigo:
                if novo not in LEAD_STATUS:
                    raise ValueError("Status inválido.")
                if novo == "fechado":
                    raise ValueError("Para fechar, use o botão Fechar venda.")
                if antigo == "fechado":
                    raise ValueError("Lead já fechado não pode mudar de etapa.")
                if novo == "perdido":
                    l.motivo_perda = _txt(d, "motivo_perda", 200, True, "Motivo da perda")
                l.status = novo
                db.session.add(LeadHistorico(lead_id=l.id, user_id=u.id, tipo="status", texto=l.motivo_perda or "",
                                             status_de=antigo, status_para=novo))
            l.versao += 1
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e), 409 if "Já existe" in str(e) else 400)
        return jsonify(ok=True, lead=_lead_json(l))

    @app.post("/api/leads/<int:lid>/nota")
    @login_obrigatorio
    def api_lead_nota(lid):
        l, d = _lead_meu(lid), _json()
        try:
            txt = _txt(d, "texto", 2000, True, "Texto")
        except ValueError as e:
            return _erro(str(e))
        db.session.add(LeadHistorico(lead_id=l.id, user_id=usuario_atual().id,
                                     tipo="contato" if d.get("tipo") == "contato" else "nota", texto=txt))
        l.atualizado_em = agora()
        db.session.commit()
        return jsonify(ok=True)

    @app.post("/api/leads/<int:lid>/fechar")
    @login_obrigatorio
    def api_lead_fechar(lid):
        l, d, u = _lead_meu(lid), _json(), usuario_atual()
        if l.status == "fechado":
            return _erro("Este lead já foi fechado.", 409)
        try:
            setup, mensal = _centavos(d.get("setup_cent", 0), "Setup"), _centavos(d.get("mensal_cent", 0), "Mensalidade")
            if setup + mensal <= 0:
                raise ValueError("Informe o valor do setup e/ou da mensalidade.")
            sid = d.get("servico_id") or l.servico_id
            if sid and not db.session.get(Servico, sid):
                raise ValueError("Serviço inexistente.")
            prop = db.session.get(Proposta, d["proposta_id"]) if d.get("proposta_id") else None
            if prop and prop.lead_id != l.id:
                raise ValueError("Proposta de outro lead.")
            ps, pm = (_pct(d.get("pct_setup")), _pct(d.get("pct_mensal"))) if u.is_admin else (None, None)
            vendedor = db.session.get(User, l.owner_id)
            venda = criar_venda(cliente_de_lead(l), vendedor, setup, mensal, sid, l, prop.id if prop else None,
                                setup_vence=_data(d.get("setup_vence")), mensal_inicio=_data(d.get("mensal_inicio")),
                                pct_setup=ps, pct_mensal=pm)
            if prop:
                prop.status = "aceita"
            l.versao += 1
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        return jsonify(ok=True, venda_id=venda.id, cliente_id=venda.cliente_id)

    # ── serviços ───────────────────────────────────────────────────────────
    def _srv_json(s):
        return dict(id=s.id, nome=s.nome, descricao=s.descricao, setup_cent=s.preco_setup_cent,
                    mensal_cent=s.preco_mensal_cent, ativo=s.ativo)

    @app.get("/api/servicos")
    @login_obrigatorio
    def api_servicos():
        stmt = select(Servico).order_by(Servico.nome)
        if not usuario_atual().is_admin:
            stmt = stmt.where(Servico.ativo.is_(True))
        return jsonify(ok=True, servicos=[_srv_json(s) for s in db.session.scalars(stmt)])

    @app.route("/api/admin/servicos", methods=["POST"])
    @app.route("/api/admin/servicos/<int:sid>", methods=["PUT"])
    @admin_obrigatorio
    def admin_servico(sid=None):
        d = _json()
        s = db.session.get(Servico, sid) if sid else Servico()
        if sid and not s:
            abort(404)
        try:
            if not sid or "nome" in d:
                s.nome = _txt(d, "nome", 120, True, "Nome")
            if "descricao" in d:
                s.descricao = _txt(d, "descricao", 2000) or ""
            if "setup_cent" in d:
                s.preco_setup_cent = _centavos(d["setup_cent"], "Setup")
            if "mensal_cent" in d:
                s.preco_mensal_cent = _centavos(d["mensal_cent"], "Mensalidade")
            if "ativo" in d:
                s.ativo = bool(d["ativo"])
            db.session.add(s)
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        return jsonify(ok=True, servico=_srv_json(s))

    # ── prospecção (Serper) ────────────────────────────────────────────────
    def _res_json(r):
        return dict(id=r.id, titulo=r.titulo, site=r.site, telefone=r.telefone, endereco=r.endereco, status=r.status, lead_id=r.lead_id)

    @app.post("/api/prospeccao")
    @login_obrigatorio
    def api_prospeccao():
        d, u = _json(), usuario_atual()
        try:
            consulta, cidade = _txt(d, "consulta", 200, True, "Segmento"), _txt(d, "cidade", 120)
        except ValueError as e:
            return _erro(str(e))
        chave = chave_do_vendedor(u, "serper")
        if not chave:
            return _erro("Cadastre sua chave Serper em Perfil antes de buscar.", 400)
        if not limitar(f"serper:{u.id}", 30, 3600):
            return _erro("Limite de 30 buscas por hora atingido.", 429)
        try:
            places = serper_places(chave, consulta, cidade or "")
        except RuntimeError as e:
            return _erro(str(e), 502)
        b = Busca(user_id=u.id, consulta=consulta, cidade=cidade)
        db.session.add(b)
        db.session.flush()
        for p in places[:20]:
            titulo = (p.get("title") or "").strip()
            if not titulo:
                continue
            db.session.add(BuscaResultado(busca_id=b.id, titulo=titulo[:200], site=(p.get("website") or "")[:300] or None,
                                          telefone=(p.get("phoneNumber") or "")[:40] or None,
                                          endereco=(p.get("address") or "")[:300] or None,
                                          raw_json=json.dumps(p, ensure_ascii=False)[:8000]))
        registrar_uso(u, "serper")
        db.session.commit()
        rs = db.session.scalars(select(BuscaResultado).where(BuscaResultado.busca_id == b.id).order_by(BuscaResultado.id))
        return jsonify(ok=True, busca_id=b.id, resultados=[_res_json(r) for r in rs])

    @app.get("/api/prospeccao")
    @login_obrigatorio
    def api_buscas():
        u = usuario_atual()
        bs = db.session.scalars(select(Busca).where(Busca.user_id == u.id).order_by(Busca.id.desc()).limit(10))
        return jsonify(ok=True, buscas=[dict(id=b.id, consulta=b.consulta, cidade=b.cidade, em=_fmt(b.criado_em)) for b in bs])

    @app.get("/api/prospeccao/<int:bid>")
    @login_obrigatorio
    def api_busca_ver(bid):
        b = db.session.get(Busca, bid)
        if not b or b.user_id != usuario_atual().id:
            abort(404)
        rs = db.session.scalars(select(BuscaResultado).where(BuscaResultado.busca_id == b.id).order_by(BuscaResultado.id))
        return jsonify(ok=True, busca=dict(id=b.id, consulta=b.consulta, cidade=b.cidade), resultados=[_res_json(r) for r in rs])

    def _resultado_meu(rid):
        r = db.session.get(BuscaResultado, rid)
        b = db.session.get(Busca, r.busca_id) if r else None
        if not r or b.user_id != usuario_atual().id:
            abort(404)
        return r, b

    @app.post("/api/prospeccao/resultados/<int:rid>/importar")
    @login_obrigatorio
    def api_resultado_importar(rid):
        r, b = _resultado_meu(rid)
        if r.status == "importado":
            return _erro("Esse resultado já virou lead.", 409)
        chave = dedupe_key(r.site, r.telefone)
        if chave and db.session.scalar(select(Lead.id).where(Lead.dedupe_key == chave)):
            r.status = "descartado"
            db.session.commit()
            return _erro("Já existe um lead com esse site ou telefone.", 409)
        l = Lead(owner_id=usuario_atual().id, empresa=r.titulo[:160], telefone=r.telefone, site=r.site,
                 segmento=b.consulta[:80], cidade=b.cidade, origem="serper", dedupe_key=chave)
        db.session.add(l)
        db.session.flush()
        r.status, r.lead_id = "importado", l.id
        db.session.add(LeadHistorico(lead_id=l.id, user_id=l.owner_id, tipo="nota", texto="Importado da prospecção"))
        db.session.commit()
        return jsonify(ok=True, lead=_lead_json(l))

    @app.post("/api/prospeccao/resultados/<int:rid>/descartar")
    @login_obrigatorio
    def api_resultado_descartar(rid):
        r, _ = _resultado_meu(rid)
        if r.status == "novo":
            r.status = "descartado"
            db.session.commit()
        return jsonify(ok=True)

    # ── IA (Groq) ──────────────────────────────────────────────────────────
    @app.post("/api/ia/mensagem")
    @login_obrigatorio
    def api_ia_mensagem():
        d, u = _json(), usuario_atual()
        l = _lead_meu(d.get("lead_id") or 0)
        chave = chave_do_vendedor(u, "groq")
        if not chave:
            return _erro("Cadastre sua chave Groq em Perfil.", 400)
        if not limitar(f"groq:{u.id}", 60, 3600):
            return _erro("Limite de 60 mensagens por hora atingido.", 429)
        canal = "WhatsApp" if d.get("canal") != "email" else "e-mail"
        prompt = (f"Escreva uma primeira mensagem de {canal} em português do Brasil, curta (até 90 palavras), cordial e sem exageros, "
                  f"da Leanttro Tecnologia (sites, sistemas e automações) para a empresa '{l.empresa}'"
                  f"{', segmento ' + l.segmento if l.segmento else ''}{', em ' + l.cidade if l.cidade else ''}. "
                  f"Assine como {u.nome}. Não invente dados sobre a empresa. Termine com uma pergunta simples.")
        try:
            texto = groq_texto(chave, prompt, "Você é um consultor comercial brasileiro, direto e educado.")
        except RuntimeError as e:
            return _erro(str(e), 502)
        registrar_uso(u, "groq")
        db.session.commit()
        return jsonify(ok=True, texto=texto)

    # ── propostas ──────────────────────────────────────────────────────────
    @app.post("/api/propostas")
    @login_obrigatorio
    def api_proposta_criar():
        d, u = _json(), usuario_atual()
        l = _lead_meu(d.get("lead_id") or 0)
        try:
            sid = d.get("servico_id") or l.servico_id
            srv = db.session.get(Servico, sid) if sid else None
            if sid and not srv:
                raise ValueError("Serviço inexistente.")
            setup = _centavos(d.get("setup_cent", srv.preco_setup_cent if srv else 0), "Setup")
            mensal = _centavos(d.get("mensal_cent", srv.preco_mensal_cent if srv else 0), "Mensalidade")
            if setup + mensal <= 0:
                raise ValueError("Informe o valor do setup e/ou da mensalidade.")
            p = Proposta(user_id=l.owner_id, lead_id=l.id, servico_id=sid, valor_setup_cent=setup, valor_mensal_cent=mensal,
                         condicoes=_txt(d, "condicoes", 3000) or "", validade=_data(d.get("validade")))
            db.session.add(p)
            db.session.flush()
            p.pdf_path = gerar_pdf_proposta(p, l.empresa, srv.nome if srv else None, db.session.get(User, l.owner_id))
            if l.status in ("novo", "em_contato", "qualificado"):
                db.session.add(LeadHistorico(lead_id=l.id, user_id=u.id, tipo="status", texto="Proposta gerada",
                                             status_de=l.status, status_para="proposta_enviada"))
                l.status = "proposta_enviada"
            else:
                db.session.add(LeadHistorico(lead_id=l.id, user_id=u.id, tipo="proposta", texto=f"Proposta #{p.id} gerada"))
            l.versao += 1
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        return jsonify(ok=True, proposta_id=p.id)

    @app.get("/api/propostas/<int:pid>/pdf")
    @login_obrigatorio
    def api_proposta_pdf(pid):
        p, u = db.session.get(Proposta, pid), usuario_atual()
        if not p or not p.pdf_path or (p.user_id != u.id and not u.is_admin):
            abort(404)
        return send_from_directory(DATA_DIR, p.pdf_path, mimetype="application/pdf", download_name=f"proposta_{p.id}.pdf")

    @app.put("/api/propostas/<int:pid>")
    @login_obrigatorio
    def api_proposta_status(pid):
        p, u, d = db.session.get(Proposta, pid), usuario_atual(), _json()
        if not p or (p.user_id != u.id and not u.is_admin):
            abort(404)
        if d.get("status") not in ("enviada", "recusada"):
            return _erro("Status inválido.")
        p.status = d["status"]
        db.session.commit()
        return jsonify(ok=True)

    # ── vendas / pagamentos ────────────────────────────────────────────────
    @app.get("/api/vendas")
    @login_obrigatorio
    def api_vendas():
        stmt = escopo(select(Venda, Cliente.empresa).join(Cliente, Cliente.id == Venda.cliente_id), Venda.vendedor_id,
                      equipe=request.args.get("equipe") == "1")
        rows = db.session.execute(stmt.order_by(Venda.id.desc()).limit(200)).all()
        return jsonify(ok=True, vendas=[dict(id=v.id, cliente=emp, cliente_id=v.cliente_id, vendedor_id=v.vendedor_id,
                                             setup_cent=v.valor_setup_cent, mensal_cent=v.valor_mensal_cent,
                                             mensal_ativa=v.mensal_ativa, fechada_em=_fmt(v.fechada_em)) for v, emp in rows])

    @app.get("/api/admin/pagamentos")
    @admin_obrigatorio
    def admin_pagamentos():
        filtro, mes = request.args.get("status", ""), request.args.get("mes", "")
        stmt = (select(Pagamento, Cliente.empresa, User.nome).join(Venda, Venda.id == Pagamento.venda_id)
                .join(Cliente, Cliente.id == Venda.cliente_id).join(User, User.id == Venda.vendedor_id))
        if re.match(r"^\d{4}-(0[1-9]|1[0-2])$", mes):
            y, m = int(mes[:4]), int(mes[5:])
            stmt = stmt.where(Pagamento.vence_em >= date(y, m, 1),
                              Pagamento.vence_em <= date(y, m, calendar.monthrange(y, m)[1]))
        rows = db.session.execute(stmt.order_by(Pagamento.vence_em).limit(500)).all()
        out = [dict(id=p.id, venda_id=p.venda_id, cliente=emp, vendedor=nome, tipo=p.tipo, competencia=p.competencia,
                    valor_cent=p.valor_cent, recebido_cent=p.valor_recebido_cent, vence_em=_fmt(p.vence_em),
                    pago_em=_fmt(p.pago_em), status=p.status) for p, emp, nome in rows]
        if filtro in ("pago", "parcial", "atrasado", "pendente"):
            out = [x for x in out if x["status"] == filtro]
        return jsonify(ok=True, pagamentos=out)

    # ── clientes / projetos ────────────────────────────────────────────────
    def _cli_json(c):
        return dict(id=c.id, owner_id=c.owner_id, empresa=c.empresa, contato=c.contato, documento=c.documento,
                    telefone=c.telefone, email=c.email, site=c.site, endereco=c.endereco, origem=c.origem,
                    observacoes=c.observacoes)

    def _cliente_meu(cid):
        c, u = db.session.get(Cliente, cid), usuario_atual()
        if not c or (c.owner_id != u.id and not u.is_admin):
            abort(404)
        return c

    def _preencher_cliente(c, d, novo=False):
        c.empresa = _txt(d, "empresa", 160, novo or "empresa" in d, "Empresa") or c.empresa
        for campo, n in (("contato", 120), ("documento", 20), ("telefone", 40), ("site", 300), ("endereco", 300)):
            if campo in d:
                setattr(c, campo, _txt(d, campo, n))
        if "email" in d:
            e = _txt(d, "email", 254)
            if e and not EMAIL_RE.match(e):
                raise ValueError("E-mail inválido.")
            c.email = e
        if "observacoes" in d:
            c.observacoes = _txt(d, "observacoes", 4000) or ""

    def _proj_json(p):
        horas = db.session.scalar(select(func.coalesce(func.sum(ProjetoHoras.horas), 0)).where(ProjetoHoras.projeto_id == p.id))
        return dict(id=p.id, cliente_id=p.cliente_id, nome=p.nome, status=p.status, prazo=_fmt(p.prazo),
                    custo_hora_cent=p.custo_hora_cent, horas=float(horas), custo_mao_obra_cent=round(float(horas) * p.custo_hora_cent),
                    observacoes=p.observacoes)

    def _proj_meu(pid):
        p = db.session.get(Projeto, pid)
        if not p:
            abort(404)
        _cliente_meu(p.cliente_id)
        return p

    @app.get("/api/clientes")
    @login_obrigatorio
    def api_clientes():
        stmt = escopo(select(Cliente), Cliente.owner_id, equipe=request.args.get("equipe") == "1")
        return jsonify(ok=True, clientes=[_cli_json(c) for c in db.session.scalars(stmt.order_by(Cliente.empresa).limit(300))])

    @app.post("/api/clientes")
    @login_obrigatorio
    def api_cliente_criar():
        c = Cliente(owner_id=usuario_atual().id, empresa="", origem="manual")
        try:
            _preencher_cliente(c, _json(), novo=True)
        except ValueError as e:
            return _erro(str(e))
        db.session.add(c)
        db.session.commit()
        return jsonify(ok=True, cliente=_cli_json(c))

    @app.get("/api/clientes/<int:cid>")
    @login_obrigatorio
    def api_cliente_ver(cid):
        c = _cliente_meu(cid)
        projetos = db.session.scalars(select(Projeto).where(Projeto.cliente_id == c.id).order_by(Projeto.id.desc()))
        vendas = db.session.scalars(select(Venda).where(Venda.cliente_id == c.id).order_by(Venda.id.desc()))
        return jsonify(ok=True, cliente=_cli_json(c),
                       projetos=[_proj_json(p) for p in projetos],
                       vendas=[dict(id=v.id, setup_cent=v.valor_setup_cent, mensal_cent=v.valor_mensal_cent,
                                    mensal_ativa=v.mensal_ativa, fechada_em=_fmt(v.fechada_em)) for v in vendas])

    @app.put("/api/clientes/<int:cid>")
    @login_obrigatorio
    def api_cliente_editar(cid):
        c = _cliente_meu(cid)
        try:
            _preencher_cliente(c, _json())
        except ValueError as e:
            return _erro(str(e))
        db.session.commit()
        return jsonify(ok=True, cliente=_cli_json(c))

    @app.post("/api/clientes/<int:cid>/venda")
    @login_obrigatorio
    def api_cliente_venda(cid):
        c, d = _cliente_meu(cid), _json()
        try:
            setup, mensal = _centavos(d.get("setup_cent", 0), "Setup"), _centavos(d.get("mensal_cent", 0), "Mensalidade")
            if setup + mensal <= 0:
                raise ValueError("Informe o valor do setup e/ou da mensalidade.")
            sid = d.get("servico_id")
            if sid and not db.session.get(Servico, sid):
                raise ValueError("Serviço inexistente.")
            v = criar_venda(c, db.session.get(User, c.owner_id), setup, mensal, sid,
                            setup_vence=_data(d.get("setup_vence")), mensal_inicio=_data(d.get("mensal_inicio")))
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        return jsonify(ok=True, venda_id=v.id)

    @app.get("/api/projetos")
    @login_obrigatorio
    def api_projetos():
        u = usuario_atual()
        stmt = select(Projeto, Cliente.empresa).join(Cliente, Cliente.id == Projeto.cliente_id)
        if not (u.is_admin and request.args.get("equipe") == "1"):
            stmt = stmt.where(Cliente.owner_id == u.id)
        rows = db.session.execute(stmt.order_by(Projeto.id.desc()).limit(200)).all()
        return jsonify(ok=True, projetos=[dict(_proj_json(p), cliente=emp) for p, emp in rows])

    @app.put("/api/projetos/<int:pid>")
    @login_obrigatorio
    def api_projeto_editar(pid):
        p, d = _proj_meu(pid), _json()
        try:
            if "nome" in d:
                p.nome = _txt(d, "nome", 160, True, "Nome")
            if d.get("status") in ("a_iniciar", "andamento", "entregue"):
                p.status = d["status"]
            if "prazo" in d:
                p.prazo = _data(d["prazo"])
            if "observacoes" in d:
                p.observacoes = _txt(d, "observacoes", 4000) or ""
            if "custo_hora_cent" in d:
                p.custo_hora_cent = _centavos(d["custo_hora_cent"], "Custo/hora")
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        db.session.commit()
        return jsonify(ok=True, projeto=_proj_json(p))

    @app.post("/api/projetos/<int:pid>/horas")
    @login_obrigatorio
    def api_projeto_horas(pid):
        p, d = _proj_meu(pid), _json()
        h = d.get("horas")
        if isinstance(h, bool) or not isinstance(h, (int, float)) or not 0 < h <= 24:
            return _erro("Horas deve ser um número entre 0 e 24.")
        try:
            db.session.add(ProjetoHoras(projeto_id=p.id, user_id=usuario_atual().id, horas=float(h),
                                        data=_data(d.get("data")) or hoje(), descricao=_txt(d, "descricao", 200)))
        except ValueError as e:
            return _erro(str(e))
        db.session.commit()
        return jsonify(ok=True, projeto=_proj_json(p))

    # ── custos e financeiro (admin) ────────────────────────────────────────
    def _custo_json(c):
        return dict(id=c.id, tipo=c.tipo, categoria=c.categoria, descricao=c.descricao, valor_cent=c.valor_cent,
                    recorrencia=c.recorrencia, data=_fmt(c.data), projeto_id=c.projeto_id)

    @app.get("/api/admin/custos")
    @admin_obrigatorio
    def admin_custos():
        rows = db.session.scalars(select(Custo).order_by(Custo.data.desc()).limit(300))
        return jsonify(ok=True, custos=[_custo_json(c) for c in rows])

    @app.post("/api/admin/custos")
    @admin_obrigatorio
    def admin_custo_criar():
        d = _json()
        try:
            if d.get("tipo") not in ("fixo", "variavel"):
                raise ValueError("Tipo deve ser fixo ou variável.")
            rec = d.get("recorrencia", "unica")
            if rec not in ("mensal", "anual", "unica"):
                raise ValueError("Recorrência inválida.")
            pid = d.get("projeto_id")
            if pid and not db.session.get(Projeto, pid):
                raise ValueError("Projeto inexistente.")
            c = Custo(tipo=d["tipo"], categoria=_txt(d, "categoria", 60, True, "Categoria"), descricao=_txt(d, "descricao", 200) or "",
                      valor_cent=_centavos(d.get("valor_cent"), "Valor"), recorrencia=rec, data=_data(d.get("data")) or hoje(),
                      projeto_id=pid or None)
            db.session.add(c)
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        return jsonify(ok=True, custo=_custo_json(c))

    @app.delete("/api/admin/custos/<int:cid>")
    @admin_obrigatorio
    def admin_custo_apagar(cid):
        c = db.session.get(Custo, cid)
        if not c:
            abort(404)
        db.session.delete(c)
        db.session.commit()
        return jsonify(ok=True)

    @app.get("/api/admin/financeiro")
    @admin_obrigatorio
    def admin_financeiro():
        mes = request.args.get("mes") or hoje().strftime("%Y-%m")
        if not re.match(r"^\d{4}-(0[1-9]|1[0-2])$", mes):
            return _erro("Mês inválido (use AAAA-MM).")
        y, m = int(mes[:4]), int(mes[5:])
        ini, fim = date(y, m, 1), date(y, m, calendar.monthrange(y, m)[1])
        pags = list(db.session.scalars(select(Pagamento)))
        recebido = sum(p.valor_recebido_cent for p in pags if p.pago_em and ini <= p.pago_em <= fim)
        do_mes = [p for p in pags if ini <= p.vence_em <= fim]
        a_receber = sum(max(p.valor_cent - p.valor_recebido_cent, 0) for p in do_mes)
        atrasado = sum(p.valor_cent - p.valor_recebido_cent for p in pags if p.status == "atrasado")
        custos = 0
        for c in db.session.scalars(select(Custo).where(Custo.data <= fim)):
            if c.recorrencia == "mensal" or (c.recorrencia == "unica" and ini <= c.data <= fim):
                custos += c.valor_cent
            elif c.recorrencia == "anual":
                custos += round(c.valor_cent / 12)
        comissoes = db.session.scalar(select(func.coalesce(func.sum(Comissao.valor_liberado_cent), 0))
                                      .join(Pagamento, Pagamento.id == Comissao.pagamento_id)
                                      .where(Pagamento.pago_em >= ini, Pagamento.pago_em <= fim)) or 0
        mrr = db.session.scalar(select(func.coalesce(func.sum(Venda.valor_mensal_cent), 0)).where(Venda.mensal_ativa.is_(True))) or 0
        return jsonify(ok=True, mes=mes, recebido_cent=recebido, a_receber_cent=a_receber, atrasado_cent=atrasado,
                       custos_cent=custos, comissoes_cent=comissoes, mrr_cent=mrr,
                       lucro_cent=recebido - custos - comissoes)

    # ── candidatos (admin) ─────────────────────────────────────────────────
    ETAPAS = ("novo", "entrevista", "teste", "aprovado", "reprovado")

    def _cand_json(c):
        return dict(id=c.id, nome=c.nome, email=c.email, telefone=c.telefone, etapa=c.etapa, notas=c.notas, user_id=c.user_id)

    @app.get("/api/admin/candidatos")
    @admin_obrigatorio
    def admin_candidatos():
        return jsonify(ok=True, candidatos=[_cand_json(c) for c in db.session.scalars(select(Candidato).order_by(Candidato.id.desc()))])

    @app.route("/api/admin/candidatos", methods=["POST"])
    @app.route("/api/admin/candidatos/<int:cid>", methods=["PUT"])
    @admin_obrigatorio
    def admin_candidato(cid=None):
        d = _json()
        c = db.session.get(Candidato, cid) if cid else Candidato()
        if cid and not c:
            abort(404)
        try:
            if not cid or "nome" in d:
                c.nome = _txt(d, "nome", 120, True, "Nome")
            if "email" in d:
                e = _txt(d, "email", 254)
                if e and not EMAIL_RE.match(e):
                    raise ValueError("E-mail inválido.")
                c.email = e
            if "telefone" in d:
                c.telefone = _txt(d, "telefone", 40)
            if "notas" in d:
                c.notas = _txt(d, "notas", 4000) or ""
            if d.get("etapa") in ETAPAS:
                c.etapa = d["etapa"]
            db.session.add(c)
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        return jsonify(ok=True, candidato=_cand_json(c))

    @app.post("/api/admin/candidatos/<int:cid>/aprovar")
    @admin_obrigatorio
    def admin_candidato_aprovar(cid):
        c = db.session.get(Candidato, cid)
        if not c:
            abort(404)
        if c.user_id:
            return _erro("Esse candidato já tem acesso.", 409)
        email = _norm(c.email)
        if not EMAIL_RE.match(email):
            return _erro("Cadastre um e-mail válido no candidato antes de aprovar.")
        temp = secrets.token_urlsafe(9)
        try:
            u = User(nome=c.nome[:80], email=email, email_norm=email, telefone=c.telefone, papel="vendedor",
                     senha_hash=generate_password_hash(temp), trocar_senha=True)
            db.session.add(u)
            db.session.flush()
            c.user_id, c.etapa = u.id, "aprovado"
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return _erro("Já existe um usuário com esse e-mail.", 409)
        return jsonify(ok=True, usuario=_user_json(u), senha_temporaria=temp)

    # ── treinamento ────────────────────────────────────────────────────────
    @app.get("/api/treinamento")
    @login_obrigatorio
    def api_treinamento():
        u = usuario_atual()
        feitos = set(db.session.scalars(select(TreinamentoProgresso.modulo_id).where(TreinamentoProgresso.user_id == u.id)))
        mods = db.session.scalars(select(TreinamentoModulo).order_by(TreinamentoModulo.ordem, TreinamentoModulo.id))
        return jsonify(ok=True, modulos=[dict(id=t.id, titulo=t.titulo, ordem=t.ordem, conteudo=t.conteudo,
                                              concluido=t.id in feitos) for t in mods])

    @app.post("/api/treinamento/<int:mid>/concluir")
    @login_obrigatorio
    def api_treinamento_concluir(mid):
        u = usuario_atual()
        if not db.session.get(TreinamentoModulo, mid):
            abort(404)
        if not db.session.get(TreinamentoProgresso, (u.id, mid)):
            db.session.add(TreinamentoProgresso(user_id=u.id, modulo_id=mid))
            db.session.commit()
        return jsonify(ok=True)

    @app.route("/api/admin/treinamento", methods=["POST"])
    @app.route("/api/admin/treinamento/<int:mid>", methods=["PUT"])
    @admin_obrigatorio
    def admin_treinamento(mid=None):
        d = _json()
        t = db.session.get(TreinamentoModulo, mid) if mid else TreinamentoModulo()
        if mid and not t:
            abort(404)
        try:
            if not mid or "titulo" in d:
                t.titulo = _txt(d, "titulo", 160, True, "Título")
            if "conteudo" in d:
                t.conteudo = _txt(d, "conteudo", 20000) or ""
            if "ordem" in d:
                if isinstance(d["ordem"], bool) or not isinstance(d["ordem"], int):
                    raise ValueError("Ordem inválida.")
                t.ordem = d["ordem"]
            db.session.add(t)
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            return _erro(str(e))
        return jsonify(ok=True, id=t.id)

    # ── materiais ──────────────────────────────────────────────────────────
    @app.get("/api/materiais")
    @login_obrigatorio
    def api_materiais():
        rows = db.session.scalars(select(Material).order_by(Material.categoria, Material.titulo))
        return jsonify(ok=True, materiais=[dict(id=x.id, titulo=x.titulo, categoria=x.categoria, link=x.link,
                                                tem_arquivo=bool(x.arquivo)) for x in rows])

    @app.post("/api/admin/materiais")
    @admin_obrigatorio
    def admin_material_criar():
        f = request.form if request.form else _json()
        arq, nome_arq = request.files.get("arquivo"), None
        try:
            titulo = _txt(f, "titulo", 160, True, "Título")
            link = _txt(f, "link", 500)
            if link and not link.lower().startswith(("http://", "https://")):
                raise ValueError("O link precisa começar com http:// ou https://.")
            if arq and arq.filename:
                nome = secrets.token_hex(6) + "_" + secure_filename(arq.filename)
                if Path(nome).suffix.lower() not in EXT_PERMITIDAS:
                    raise ValueError("Tipo de arquivo não permitido.")
                (DATA_DIR / "uploads").mkdir(parents=True, exist_ok=True)
                arq.save(DATA_DIR / "uploads" / nome)
                nome_arq = nome
            if not link and not nome_arq:
                raise ValueError("Envie um arquivo ou informe um link.")
        except ValueError as e:
            return _erro(str(e))
        x = Material(titulo=titulo, categoria=_txt(f, "categoria", 60) or "geral", arquivo=nome_arq, link=link)
        db.session.add(x)
        db.session.commit()
        return jsonify(ok=True, id=x.id)

    @app.delete("/api/admin/materiais/<int:mid>")
    @admin_obrigatorio
    def admin_material_apagar(mid):
        x = db.session.get(Material, mid)
        if not x:
            abort(404)
        if x.arquivo:
            (DATA_DIR / "uploads" / x.arquivo).unlink(missing_ok=True)
        db.session.delete(x)
        db.session.commit()
        return jsonify(ok=True)

    @app.get("/api/materiais/<int:mid>/arquivo")
    @login_obrigatorio
    def api_material_arquivo(mid):
        x = db.session.get(Material, mid)
        if not x or not x.arquivo:
            abort(404)
        return send_from_directory(DATA_DIR / "uploads", x.arquivo, as_attachment=True)

    # ── erros em JSON para /api ────────────────────────────────────────────
    @app.errorhandler(404)
    def _e404(_e):
        return (jsonify(ok=False, erro="Não encontrado."), 404) if request.path.startswith("/api/") else ("Não encontrado.", 404)

    @app.errorhandler(405)
    def _e405(_e):
        return jsonify(ok=False, erro="Método não permitido."), 405

    @app.errorhandler(413)
    def _e413(_e):
        return jsonify(ok=False, erro="Arquivo grande demais."), 413

    @app.errorhandler(500)
    def _e500(_e):
        db.session.rollback()
        return jsonify(ok=False, erro="Erro interno. Tente de novo."), 500

    return app


app = criar_app()


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def init_db():
    """Idempotente: cria tabelas, aplica migrações, semeia config e sincroniza o admin com o .env."""
    with app.app_context():
        db.create_all()
        info = db.session.get(SchemaInfo, 1)
        if info is None:
            db.session.add(SchemaInfo(id=1, versao=SCHEMA_VERSAO))
        elif info.versao < SCHEMA_VERSAO:
            # futuras migrações: _add_col("tabela", "coluna", "TIPO DEFAULT x")
            info.versao = SCHEMA_VERSAO
        for k, v in CONFIG_PADRAO.items():
            if db.session.get(Config, k) is None:
                db.session.add(Config(chave=k, valor=v))
        db.session.commit()

        email, senha = _norm(_env("ADMIN_EMAIL")), os.environ.get("ADMIN_PASS", "")
        if email and senha:
            u = db.session.scalar(select(User).where(User.email_norm == email))
            if u is None:
                db.session.add(User(nome=_env("ADMIN_NOME") or "Administrador", email=email, email_norm=email,
                                    papel="admin", senha_hash=generate_password_hash(senha)))
            else:
                u.papel, u.status = "admin", "ativo"
                if not check_password_hash(u.senha_hash, senha):
                    u.senha_hash = generate_password_hash(senha)
                    u.sessao_versao += 1
            db.session.commit()
        elif not db.session.scalar(select(User).where(User.papel == "admin")):
            print("AVISO: defina ADMIN_EMAIL e ADMIN_PASS no .env para criar o administrador.", file=sys.stderr)
        manter_mensalidades_todas()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "init-db":
        init_db()
        print("banco ok")
    elif cmd == "run":
        init_db()
        app.run(host=_env("HOST") or "127.0.0.1", port=_int("PORT", 8000), debug=DEBUG)
    else:
        sys.exit("Uso: python app.py [run | init-db]")
