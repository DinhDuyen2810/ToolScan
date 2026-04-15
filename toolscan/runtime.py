from flask import Flask


def create_app() -> Flask:
    from .legacy_app import app as legacy_app
    return legacy_app


app = create_app()
