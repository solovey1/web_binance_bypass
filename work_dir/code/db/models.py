from datetime import datetime
from typing import TypeAlias, Annotated, Optional, Final, Any

from sqlalchemy import MetaData, DateTime, ForeignKey, Function, func
from sqlalchemy.orm import Mapped, mapped_column, relationship, DeclarativeBase

# Декларативная база вместо MetaData()
class Base(DeclarativeBase):
    metadata = MetaData()

Int16: TypeAlias = Annotated[int, 16]
Int32: TypeAlias = Annotated[int, 32]
Int64: TypeAlias = Annotated[int, 64]

NowFunc: Final[Function[Any]] = func.timezone("UTC", func.now())


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(server_default=NowFunc)
    updated_at: Mapped[datetime] = mapped_column(server_default=NowFunc, server_onupdate=NowFunc)

class Bypass(Base, TimestampMixin):
    __tablename__ = "bypass"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="NO ACTION")
    )
    proxy: Mapped[str] = mapped_column()
    tag: Mapped[str] = mapped_column(unique=True, nullable=False)
    is_deleted: Mapped[bool] = mapped_column(default=False, nullable=False)

    user: Mapped["User"] = relationship(
        "User",
        back_populates="bypass",
    )

class ExchangeBypass(Base, TimestampMixin):
    __tablename__ = "exchange_bypass"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="NO ACTION")
    )
    service: Mapped[str] = mapped_column(index=True)  # "binance", "okx", ...
    proxy: Mapped[str] = mapped_column()
    tag: Mapped[str] = mapped_column(unique=True, nullable=False)
    is_deleted: Mapped[bool] = mapped_column(default=False, nullable=False)

class SumsubWebSDK(Base, TimestampMixin):

    __tablename__ = "sumsub_websdk"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="NO ACTION")
    )
    tag: Mapped[str] = mapped_column(unique=True, nullable=False)
    mark: Mapped[str] = mapped_column(nullable=True)
    access_token: Mapped[str] = mapped_column()
    lang: Mapped[str] = mapped_column(default="en", nullable=False)
    is_deleted: Mapped[bool] = mapped_column(default=False, nullable=False)


    user: Mapped["User"] = relationship(
        "User",
        back_populates="sumsub_websdk",
    )

class Subscription(Base, TimestampMixin):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship(
        "User",
        back_populates="subscriptions",
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[Int64] = mapped_column(primary_key=True, autoincrement=True)
    telegram_id: Mapped[Int64] = mapped_column(unique=True)
    name: Mapped[str] = mapped_column()
    blocked_at: Mapped[Optional[datetime]] = mapped_column()
    test_access_used: Mapped[bool] = mapped_column(default=False)

    subscriptions: Mapped[list["Subscription"]] = relationship(
        "Subscription",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    bypass: Mapped[list["Bypass"]] = relationship(
        "Bypass",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    sumsub_websdk: Mapped[list["SumsubWebSDK"]] = relationship(
        "SumsubWebSDK",
        back_populates="user",
        cascade="all, delete-orphan",
    )