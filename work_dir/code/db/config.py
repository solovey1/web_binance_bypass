import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

DATABASE_URL = (
    f"postgresql+asyncpg://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}"
    f"@{os.getenv('DB_HOST')}:5432/{os.getenv('DB_NAME')}"
)

engine = create_async_engine(DATABASE_URL, echo=False, future=True)

async_session_maker = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)