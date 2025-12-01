# src/database.py

import enum
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, Float, Boolean, Enum, JSON
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.sql import func
from .config import DATABASE_URL

Base = declarative_base()

class Repository(Base):
    __tablename__ = 'repository'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False, unique=True)
    primary_branch = Column(String, nullable=True)
    last_commit_hash = Column(String, nullable=True)
    needs_scan = Column(Boolean, default=False)
    periodic_scan_enabled = Column(Boolean, default=False)
    periodic_scan_interval = Column(Integer, default=86400) # 24 hours
    sast_exclusions = Column(Text, nullable=True)
    
    # Test Configuration
    test_command = Column(String, nullable=True)
    use_venv = Column(Boolean, default=False)
    python_version = Column(String, nullable=True)
    test_container = Column(String, nullable=True)
    
    # New Column: Override global setting. True=Container, False=Local, None=Use Global
    run_tests_in_container = Column(Boolean, nullable=True, default=None) 
    
    scans = relationship("Scan", back_populates="repository")

class ScanStatus(enum.Enum):
    QUEUED = 'queued'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'

class Scan(Base):
    __tablename__ = 'scan'
    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey('repository.id'), nullable=False)
    scan_type = Column(String, default='commit')
    status = Column(Enum(ScanStatus, values_callable=lambda x: [e.value for e in x]), default=ScanStatus.QUEUED)
    status_message = Column(String)
    triggering_commit_hash = Column(String)
    job_id = Column(String)
    branch = Column(String, nullable=True)
    progress = Column(Integer, default=0)
    total_progress = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    auto_patch_enabled = Column(Boolean, default=False)
    generate_test_script = Column(Boolean, default=False)
    test_output = Column(Text, nullable=True)
    languages = Column(JSON, nullable=True)
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    quality_metrics = relationship("QualityMetric", back_populates="scan", cascade="all, delete-orphan")
    repository = relationship("Repository", back_populates="scans")

class Finding(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan.id'))
    file_path = Column(String)
    line_number = Column(Integer)
    code_snippet = Column(String)
    description = Column(String)
    severity = Column(String)
    confidence_score = Column(Float)
    status = Column(String, default='new')
    cve_id = Column(String)
    description_text = Column(Text, nullable=True) # Added for caching parsed text
    description_url = Column(String, nullable=True) # Added for caching url
    rule_id = Column(String, nullable=True) # Added for caching rule id
    scan = relationship("Scan", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")
    patch = relationship("Patch", uselist=False, back_populates="finding", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'description': self.description,
            'severity': self.severity,
            'confidence_score': self.confidence_score,
            'status': self.status,
            'cve_id': self.cve_id,
        }

class Evidence(Base):
    __tablename__ = 'evidence'
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey('findings.id'), nullable=False)
    type = Column(String, nullable=False)
    content = Column(Text)
    finding = relationship("Finding", back_populates="evidence")

class Patch(Base):
    __tablename__ = 'patch'
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey('findings.id'), nullable=False)
    generated_patch_diff = Column(Text)
    pull_request_url = Column(String)
    finding = relationship("Finding", back_populates="patch")

class QualityInterpretation(Base):
    __tablename__ = 'quality_interpretation'
    id = Column(Integer, primary_key=True)
    quality_metric_id = Column(Integer, ForeignKey('quality_metric.id'))
    interpretation = Column(String)
    quality_metric = relationship("QualityMetric", back_populates="interpretation")
    chat_messages = relationship("ChatMessage", back_populates="quality_interpretation")

class QualityMetric(Base):
    __tablename__ = 'quality_metric'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan.id'))
    file_path = Column(String)
    # Per-file metrics
    cyclomatic_complexity = Column(Integer)
    code_churn = Column(Integer)
    sloc = Column(Integer)
    lloc = Column(Integer)
    comments = Column(Integer)
    halstead_volume = Column(Float)
    maintainability_index = Column(Float)
    bug_risk_score = Column(Float)
    # Project-wide metrics
    code_coverage = Column(Float)
    tests_passing = Column(Integer)
    duplicated_lines = Column(Integer)
    linter_issues = Column(Integer)
    coupling = Column(Float)
    cohesion = Column(Float)
    scan = relationship("Scan", back_populates="quality_metrics")
    interpretation = relationship("QualityInterpretation", uselist=False, back_populates="quality_metric")

class ChatMessage(Base):
    __tablename__ = 'chat_message'
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey('findings.id'))
    quality_interpretation_id = Column(Integer, ForeignKey('quality_interpretation.id'))
    message = Column(Text, nullable=False)
    sender = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    finding = relationship("Finding")
    quality_interpretation = relationship("QualityInterpretation", back_populates="chat_messages")

engine = create_engine(DATABASE_URL)
_Session = sessionmaker(bind=engine)

def init_db():
    """Creates all tables in the database."""
    Base.metadata.create_all(engine)

def reset_db():
    """Drops all tables and recreates them."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

def get_session():
    """Returns a new session class."""
    return _Session