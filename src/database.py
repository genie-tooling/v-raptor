from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, Float
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.sql import func
from .config import DATABASE_URL

Base = declarative_base()

class Repository(Base):
    __tablename__ = 'repository'
    id = Column(Integer, primary_key=True)
    primary_branch = Column(String, nullable=False)
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

    scan = relationship("Scan", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")
    patch = relationship("Patch", uselist=False, back_populates="finding", cascade="all, delete-orphan")

class Evidence(Base):

    __tablename__ = 'evidence'

    id = Column(Integer, primary_key=True)

    finding_id = Column(Integer, ForeignKey('findings.id'), nullable=False)

    type = Column(String, nullable=False) # 'log', 'test_output', 'tool_report'

    content = Column(Text)

    finding = relationship("Finding", back_populates="evidence")



class Patch(Base):



    __tablename__ = 'patch'



    id = Column(Integer, primary_key=True)



    finding_id = Column(Integer, ForeignKey('findings.id'), nullable=False)



    generated_patch_diff = Column(Text)



    pull_request_url = Column(String)



    finding = relationship("Finding", back_populates="patch")







class ChatMessage(Base):







    __tablename__ = 'chat_message'







    id = Column(Integer, primary_key=True)







    finding_id = Column(Integer, ForeignKey('findings.id'), nullable=False)







    message = Column(Text, nullable=False)







    sender = Column(String, nullable=False) # 'user' or 'assistant'







    created_at = Column(DateTime(timezone=True), server_default=func.now())







    finding = relationship("Finding")















class QualityMetric(Base):







    __tablename__ = 'quality_metric'







    id = Column(Integer, primary_key=True)







    scan_id = Column(Integer, ForeignKey('scan.id'), nullable=False)







    file_path = Column(String, nullable=False)







    cyclomatic_complexity = Column(Integer, nullable=False)







    code_churn = Column(Integer, nullable=False)







    scan = relationship("Scan")





engine = create_engine(DATABASE_URL)

_Session = sessionmaker(bind=engine)



def init_db():

    """Creates all tables in the database."""

    Base.metadata.create_all(engine)



def get_session():

    """Returns a new session class."""

    return _Session