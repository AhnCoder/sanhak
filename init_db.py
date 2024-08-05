from sqlalchemy import create_engine
from database import Base
from models import User, AuthPhone, AuthToken
from dotenv import load_dotenv
import os

# .env 파일의 환경 변수를 로드합니다.
load_dotenv()

# 환경 변수에서 DATABASE_URL을 가져옵니다.
DATABASE_URL = os.getenv("DATABASE_URL")

# 데이터베이스 엔진 생성
engine = create_engine(DATABASE_URL)


def reset_database():
    # 기존 테이블 삭제
    Base.metadata.drop_all(bind=engine)
    # 테이블 생성
    Base.metadata.create_all(bind=engine)
    print("Database has been reset and initialized.")


if __name__ == "__main__":
    reset_database()