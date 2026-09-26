from app.core.config import _load_process_settings

def test_process_settings_preserve_native_postgresql_dsn(monkeypatch):
    native="postgresql://u:p@db.internal/testdb?sslmode=require"
    monkeypatch.setenv("APP_ENV","test")
    monkeypatch.setenv("DATABASE_URL",native)
    monkeypatch.setenv("REDIS_URL","redis://127.0.0.1:6379/0")
    monkeypatch.delenv("DATABASE_URL_FILE",raising=False)
    monkeypatch.delenv("REDIS_URL_FILE",raising=False)
    process_settings=_load_process_settings()
    assert process_settings.database_url==native
