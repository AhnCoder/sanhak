from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

# .env 파일의 환경 변수를 로드합니다.
load_dotenv()

# 환경 변수에서 DATABASE_URL을 가져옵니다.
DATABASE_URL = os.getenv("DATABASE_URL")

# 데이터베이스 엔진 생성
engine = create_engine(DATABASE_URL)

# 세션 로컬 클래스 생성
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 베이스 클래스 생성
Base = declarative_base()