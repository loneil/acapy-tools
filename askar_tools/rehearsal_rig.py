"""Rehearsal rig for the resume-capable mt-convert-to-mw converter.

Provisions a realistic multitenant fixture with real aries-askar stores
(admin store with wallet_records + multitenant_sub_wallet with per-tenant
profiles, items, and keys), then exercises the converter end to end:

  Scenario A - fresh conversion of all tenants (happy path).
  Scenario B - a leftover/garbage target DB exists -> drop + redo path.
  Scenario C - copy fails mid-run for one tenant (simulated stall/kill) ->
               non-zero exit, sub wallet retained; re-run resumes: completed
               tenants verify+skip, the failed one converts, sub wallet drops.

Usage (from the acapy-tools repo root, in a venv with the project deps):

  python path/to/rehearsal_rig.py sqlite
  python path/to/rehearsal_rig.py postgres postgres://user:pass@host:5432

For postgres, pass the server URI *without* a database path; the rig uses
databases named admin_rehearsal / multitenant_sub_wallet and tenant names
below on that server, and expects the user to have CREATEDB rights.
NEVER point this at a real environment.
"""

import asyncio
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

from aries_askar import Key, KeyAlg, Store

REPO_HINT = "run from the acapy-tools repo root (askar_tools importable)"
sys.path.insert(0, ".")

try:
    from askar_tools.error import ConversionError
    from askar_tools.multi_wallet_converter import MultiWalletConverter
    from askar_tools.pg_connection import PgConnection
    from askar_tools.sqlite_connection import SqliteConnection
except ImportError as e:
    raise SystemExit(f"cannot import askar_tools ({e}) - {REPO_HINT}")

ADMIN_NAME = "admin_rehearsal"
ADMIN_KEY = "insecure-admin-key"
SUB_WALLET_NAME = "multitenant_sub_wallet"

# One fat tenant + near-empty tail, mirroring the observed dev skew.
# Wallet names deliberately include spaces and mixed case.
TENANTS = [
    ("Big Tenant A", 400),
    ("small Tenant b", 12),
    ("tiny-c", 1),
]


def tenant_record(name, wallet_key):
    # ARGON2I_MOD everywhere, matching Traction tenants (the converter
    # requires the tenant kdm to equal the sub wallet store's kdm).
    return {
        "settings": {
            "wallet.id": f"{name}-id",
            "wallet.name": name,
            "wallet.key": wallet_key,
            "wallet.key_derivation_method": "ARGON2I_MOD",
        }
    }


async def provision(base_uri_for):
    """Provision admin + sub wallet stores with tenant profiles/items/keys."""
    admin_store = await Store.provision(
        base_uri_for(ADMIN_NAME),
        key_method="kdf:argon2i:mod",
        pass_key=ADMIN_KEY,
        recreate=True,
    )
    sub_store = await Store.provision(
        base_uri_for(SUB_WALLET_NAME),
        key_method="kdf:argon2i:mod",
        pass_key=ADMIN_KEY,
        recreate=True,
    )

    records = []
    for name, item_count in TENANTS:
        wallet_key = f"{name}-tenant-key"
        record = tenant_record(name, wallet_key)
        records.append(record)
        wallet_id = record["settings"]["wallet.id"]

        async with admin_store.session() as session:
            await session.insert("wallet_record", wallet_id, value_json=record)

        await sub_store.create_profile(wallet_id)
        async with sub_store.session(profile=wallet_id) as session:
            for i in range(item_count):
                category = f"cat_{i % 5}"
                await session.insert(
                    category, f"item-{i}", f"value-{i}".encode(), {"idx": str(i)}
                )
            # A couple of key records so key-count verification is exercised
            for k in range(2):
                await session.insert_key(
                    f"key-{k}", Key.generate(KeyAlg.ED25519)
                )

    await admin_store.close()
    await sub_store.close()
    return records


def make_conn(admin_uri):
    if admin_uri.startswith("sqlite"):
        return SqliteConnection(admin_uri)
    return PgConnection(admin_uri)


async def run_converter(admin_uri, expect_failure=False, patch_copy_fail_for=None):
    """Run the converter; optionally make copy_to fail for one wallet name."""
    conn = make_conn(admin_uri)
    await conn.connect()
    converter = MultiWalletConverter(
        conn=conn,
        wallet_name=ADMIN_NAME,
        wallet_key=ADMIN_KEY,
        wallet_key_derivation_method="ARGON2I_MOD",
        sub_wallet_name=SUB_WALLET_NAME,
    )

    context = None
    if patch_copy_fail_for:
        real_convert = MultiWalletConverter.convert_tenant_wallet

        async def failing_convert(self, wallet_record):
            if wallet_record["settings"]["wallet.name"] == patch_copy_fail_for:
                raise RuntimeError("simulated stall/kill during copy")
            return await real_convert(self, wallet_record)

        context = mock.patch.object(
            MultiWalletConverter, "convert_tenant_wallet", failing_convert
        )

    try:
        if context:
            with context:
                await converter.run()
        else:
            await converter.run()
        failed = False
    except ConversionError as e:
        failed = True
        print(f"(converter exited with ConversionError: {e.message})")
    if failed != expect_failure:
        raise SystemExit(
            f"FAIL: expected failure={expect_failure}, got failure={failed}"
        )


async def check_tenant_stores(base_uri_for, records, expect_sub_wallet_gone):
    """Independently verify each tenant DB opens and has only its profile."""
    for record in records:
        settings = record["settings"]
        store = await Store.open(
            base_uri_for(settings["wallet.name"]),
            key_method="kdf:argon2i:mod",
            pass_key=settings["wallet.key"],
        )
        profiles = list(await store.list_profiles())
        assert profiles == [settings["wallet.id"]], profiles
        count = 0
        async for _ in store.scan():
            count += 1
        expected = dict(TENANTS)[settings["wallet.name"]]
        assert count == expected, f"{settings['wallet.name']}: {count} != {expected}"
        await store.close()

    sub_gone = False
    try:
        store = await Store.open(
            base_uri_for(SUB_WALLET_NAME), pass_key=ADMIN_KEY
        )
        await store.close()
    except Exception:
        sub_gone = True
    assert sub_gone == expect_sub_wallet_gone, (
        f"sub wallet gone={sub_gone}, expected {expect_sub_wallet_gone}"
    )


def make_base_uri_for(mode, server=None):
    """Build a fresh (base_uri_for, cleanup) pair for one scenario."""
    if mode == "sqlite":
        base = Path(tempfile.mkdtemp(prefix="mtconvert_rehearsal_"))

        def base_uri_for(name):
            (base / name).mkdir(exist_ok=True)
            return f"sqlite://{(base / name / 'sqlite.db').as_posix()}"

        return base_uri_for, lambda: shutil.rmtree(base, ignore_errors=True)

    def base_uri_for(name):
        return f"{server}/{name}"

    return base_uri_for, lambda: None


async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "sqlite"
    server = None
    if mode == "postgres":
        server = sys.argv[2].rstrip("/")
    elif mode != "sqlite":
        raise SystemExit("mode must be sqlite or postgres")

    print("\n=== Scenario A: fresh conversion ===")
    base_uri_for, cleanup = make_base_uri_for(mode, server)
    try:
        records = await provision(base_uri_for)
        await run_converter(base_uri_for(ADMIN_NAME))
        await check_tenant_stores(base_uri_for, records, expect_sub_wallet_gone=True)
        print("Scenario A PASSED")
    finally:
        cleanup()

    print("\n=== Scenario B: leftover garbage target -> drop + redo ===")
    base_uri_for, cleanup = make_base_uri_for(mode, server)
    try:
        records = await provision(base_uri_for)
        # Fake a leftover: a store at the tenant path that opens with the
        # tenant's key but has the wrong contents (default profile instead of
        # the tenant's) — converter must drop + redo, not destroy-and-quit.
        # (A wrong-key leftover exercises the same path via the cannot-open
        # branch; on Windows/sqlite a failed open can hold a file lock, so
        # that variant is best exercised in postgres mode.)
        leftover_record = next(
            r for r in records if r["settings"]["wallet.name"] == TENANTS[1][0]
        )
        leftover = await Store.provision(
            base_uri_for(TENANTS[1][0]),
            key_method="kdf:argon2i:mod",
            pass_key=leftover_record["settings"]["wallet.key"],
            recreate=True,
        )
        await leftover.close()
        await run_converter(base_uri_for(ADMIN_NAME))
        await check_tenant_stores(base_uri_for, records, expect_sub_wallet_gone=True)
        print("Scenario B PASSED")
    finally:
        cleanup()

    print("\n=== Scenario C: mid-run failure, then resume ===")
    base_uri_for, cleanup = make_base_uri_for(mode, server)
    try:
        records = await provision(base_uri_for)
        # First run: one tenant fails mid-copy -> exit non-zero, sub wallet stays
        await run_converter(
            base_uri_for(ADMIN_NAME),
            expect_failure=True,
            patch_copy_fail_for=TENANTS[1][0],
        )
        # Re-run: completed tenants verify and skip, the failed one converts,
        # and the sub wallet drops
        await run_converter(base_uri_for(ADMIN_NAME))
        await check_tenant_stores(base_uri_for, records, expect_sub_wallet_gone=True)
        print("Scenario C PASSED")
    finally:
        cleanup()

    print("\nALL SCENARIOS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
