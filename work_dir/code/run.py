from logging.config import dictConfig

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

# Binance gateway is kept but commented out for now (we are testing OKX here;
# the two services will live in separate projects later). To serve Binance
# instead, register binance_gateway_router and comment out the OKX one.
# from routers.proxy import router as binance_gateway_router
from routers.okx import router as okx_gateway_router

from utils.logging_ import LOGGING

app = FastAPI(docs_url=None, redoc_url=None)


dictConfig(LOGGING)

# OKX gateway is the primary router (subdomain is only a proxy key).
app.include_router(okx_gateway_router)
# app.include_router(binance_gateway_router)
