"""Minimal safe error pages for browser requests."""

from flask import Flask, render_template


def register_error_handlers(app: Flask) -> None:
    for code in (400, 403, 404, 500):

        def handler(error, status=code):
            return render_template(f"errors/{status}.html"), status

        app.register_error_handler(code, handler)
