from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, Float
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.sql import func
from .config import DATABASE_URL

Base = declarative_base()

class Repository(Base):
    __tablename__ = 'repository'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False, unique=True)
    scans = relationship("Scan", back_populates="repository")

class Scan(Base):
    __tablename__ = 'scan'
    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey('repository.id'), nullable=False)
    scan_type = Column(String, default='commit')
    status = Column(String, default='pending')
    triggering_commit_hash = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    repository = relationship("Repository", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = 'finding'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan.id'), nullable=False)
    file_path = Column(String)
    line_number = Column(Integer)
    code_snippet = Column(Text)
    description = Column(Text)
    severity = Column(String, default='Medium')
    confidence_score = Column(Float)
    status = Column(String, default='New') # New, Confirmed, Patched, Ignored
    scan = relationship("Scan", back_populates="findings")
    patch = relationship("Patch", uselist=False, back_populates="finding")
    evidence = relationship("Evidence", back_populates="finding")

class Evidence(Base):
    __tablename__ = 'evidence'
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey('finding.id'), nullable=False)
    type = Column(String, nullable=False) # 'log', 'test_output', 'tool_report'
    content = Column(Text)
    finding = relationship("Finding", back_populates="evidence")

class Patch(Base):
    __tablename__ = 'patch'
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey('finding.id'), nullable=False)
    generated_patch_diff = Column(Text)
    pull_request_url = Column(String)
    finding = relationship("Finding", back_populates="patch")

class Secret(Base):
    __tablename__ = 'secret'
    id = Column(Integer, primary_key=True)
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False)
    commit_hash = Column(String, nullable=False)
    description = Column(String, nullable=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now())


engine = create_engine(DATABASE_URL)
_Session = sessionmaker(bind=engine)

def init_db():
    """Creates all tables in the database."""
    Base.metadata.create_all(engine)

def get_session():
    """Returns a new session class."""
    return _Session