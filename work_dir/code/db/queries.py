from datetime import datetime

from asyncache import cached
from cachetools import TTLCache
from sqlalchemy import desc, or_, select, func
from sqlalchemy.sql import and_

from .config import async_session_maker
from .models import Bypass, Subscription, SumsubWebSDK, ExchangeBypass

cache = TTLCache(maxsize=1024, ttl=180)

@cached(cache)
async def get_proxy_for_sub(sub: str) -> str | None:
    async with async_session_maker() as session:
        stmt = (
            select(Bypass.proxy)
            .join(Subscription, Subscription.user_id == Bypass.user_id)
            .where(
                Bypass.tag == sub,
                or_(Bypass.is_deleted.is_(False), Bypass.is_deleted.is_(None)),
                Subscription.valid_until > func.now(),
            )
            .order_by(desc(Bypass.created_at))
            .limit(1)
        )
        return await session.scalar(stmt)

@cached(cache)
async def get_proxy_for_exchange_sub(service: str, sub: str) -> str | None:
    async with async_session_maker() as session:
        stmt = (
            select(ExchangeBypass.proxy)
            .join(Subscription, Subscription.user_id == ExchangeBypass.user_id)
            .where(
                ExchangeBypass.service == service,
                ExchangeBypass.tag == sub,
                ExchangeBypass.is_deleted.is_(False),
                Subscription.valid_until > func.now(),
            )
            .order_by(desc(ExchangeBypass.created_at))
            .limit(1)
        )
        return await session.scalar(stmt)

async def get_websdk_by_tag(tag: str) -> SumsubWebSDK | None:
    async with async_session_maker() as session:
        stmt = (
            select(SumsubWebSDK)
            .where(
                SumsubWebSDK.tag == tag,
                or_(SumsubWebSDK.is_deleted.is_(False), SumsubWebSDK.is_deleted.is_(None)),
            )
            .order_by(desc(SumsubWebSDK.created_at))
            .limit(1)
        )
        res = await session.execute(stmt)
        return res.scalar_one_or_none()

async def create_websdk(
    tag: str,
    access_token: str,
    lang: str | None = None,
) -> SumsubWebSDK:
    async with async_session_maker() as session:
        check_by_tag = await get_websdk_by_tag(tag)
        if check_by_tag:
            check_by_tag.access_token = access_token
            check_by_tag.lang = lang
            session.add(check_by_tag)
            await session.flush()
            await session.commit()
            return check_by_tag

        new_row = SumsubWebSDK(
            tag=tag,
            access_token=access_token,
            lang=lang,
            user_id=1
        )
        session.add(new_row)
        await session.flush()
        await session.commit()
        return new_row

async def get_or_create_bypass_record_by_proxy(
    user_id: int,
    proxy: str,
    tag: str,
    is_deleted: bool = False,
    created_at: datetime | None = None,
    update_tag_if_different: bool = False,  # сохраняем параметр для совместимости, но не используем
) -> tuple[str, bool]:
    if created_at is None:
        created_at = datetime.utcnow()

    async with async_session_maker() as session:
        stmt_get = (
            select(Bypass.tag)
            .where(
                and_(
                    Bypass.proxy == proxy,
                    or_(Bypass.is_deleted == False, Bypass.is_deleted.is_(None)),
                )
            )
            .order_by(desc(Bypass.created_at))
            .limit(1)
        )
        res = await session.execute(stmt_get)
        row = res.fetchone()

        if row:
            existing_tag = row[0]
            return existing_tag, False

        # ORM-вставка
        new_row = Bypass(
            user_id=user_id,
            proxy=proxy,
            tag=tag,
            is_deleted=is_deleted,
            created_at=created_at,
        )
        session.add(new_row)
        await session.flush()
        await session.commit()
        new_tag = new_row.tag

    try:
        get_proxy_for_sub.cache_invalidate(tag)
    except Exception:
        try:
            get_proxy_for_sub.cache_clear()
        except Exception:
            pass

    return new_tag, True