"""WP-Hunter Server package."""


def create_app():
    """Lazily import and return the FastAPI application instance."""
    from wp_hunter.server.app import create_app as _create_app

    return _create_app()


__all__ = ["create_app"]
