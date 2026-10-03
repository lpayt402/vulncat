"""Verify a full dump/restore in the disposable PostgreSQL CI job only."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict


def snapshot(connection: psycopg.Connection) -> dict[str, str]:
    tables = connection.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name"
    ).fetchall()
    result = {}
    for (name,) in tables:
        rows = connection.execute(
            sql.SQL("SELECT row_to_json(t)::text FROM {} t").format(sql.Identifier(name))
        )
        text = "\n".join(sorted(row[0] for row in rows))
        result[name] = hashlib.sha256(text.encode()).hexdigest()
    return result


def main() -> None:
    if os.environ.get("VWB_RESTORE_QA") != "1":
        raise RuntimeError("Run only in the disposable CI restoration job")
    url = os.environ["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://", 1)
    config = conninfo_to_dict(url)
    if config.get("host") != "127.0.0.1" or config.get("dbname") != "vwb_test":
        raise RuntimeError("QA is restricted to the fixed disposable loopback test database")
    dump, restore = shutil.which("pg_dump"), shutil.which("pg_restore")
    if not dump or not restore:
        raise RuntimeError("The hosted runner needs PostgreSQL dump/restore clients")
    output = Path("output/qa")
    output.mkdir(parents=True, exist_ok=True)
    backup = output / "synthetic-persistence.backup"
    env = {
        **os.environ,
        **{
            "PG" + key.upper(): value
            for key, value in config.items()
            if key in {"host", "port", "user", "password"}
        },
        "PGDATABASE": "vwb_test",
    }
    destination = "vwb_restore_" + uuid.uuid4().hex
    with psycopg.connect(url, autocommit=True) as original:
        before = snapshot(original)
        assert original.execute("SELECT count(*) FROM source_observations").fetchone()[0] >= 3
        assert original.execute("SELECT count(*) FROM exposure_decisions").fetchone()[0] >= 3
        subprocess.run(  # noqa: S603 -- resolved CI client; fixed local backup path and arguments
            [dump, "--format=custom", "--file", str(backup)], env=env, check=True
        )
        original.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(destination)))
        try:
            subprocess.run(  # noqa: S603 -- resolved CI client; UUID-named disposable target only
                [restore, "--exit-on-error", "--dbname", destination, str(backup)], env=env, check=True
            )
            with psycopg.connect(**{**config, "dbname": destination}, autocommit=True) as restored:
                assert snapshot(restored) == before
                try:
                    restored.execute("UPDATE source_observations SET parser_version = 'tampered'")
                except psycopg.errors.RaiseException as exc:
                    assert "immutable" in str(exc)
                else:
                    raise AssertionError("Restored database lost evidence immutability")
                for table in ("exposure_decisions", "exposure_node_facts", "exposure_versions"):
                    try:
                        restored.execute(sql.SQL("DELETE FROM {}").format(sql.Identifier(table)))
                    except psycopg.errors.RaiseException as exc:
                        assert "immutable" in str(exc)
                    else:
                        raise AssertionError("Restored database lost service history immutability")
                assert snapshot(restored) == before
            assert snapshot(original) == before
            print(
                json.dumps(
                    {
                        "restoration": "passed",
                        "tables_compared": len(before),
                        "original_unchanged": True,
                        "restored_immutability": True,
                        "restored_exposure_immutability": True,
                    }
                )
            )
        finally:
            original.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(destination)))


if __name__ == "__main__":
    main()
