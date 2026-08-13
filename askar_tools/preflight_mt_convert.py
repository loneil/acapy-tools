"""Read-only pre-flight check for the `mt-convert-to-mw` migration strategy.

Purpose
-------
Before running the real single-wallet -> multi-wallet conversion
(`askar_tools.multi_wallet_converter.MultiWalletConverter`) against a live
Traction/ACA-Py Crunchy database, run this first. It exercises *exactly the
access paths the converter needs* -- database connectivity, the admin-role
`CREATE DATABASE` privilege, opening the askar admin + sub-wallet stores, and
reading every tenant profile that would be migrated -- but performs
**ZERO WRITES**. It reports what would succeed or fail so a maintenance window
is not spent discovering an access problem mid-conversion.

Same arguments as the real tool
-------------------------------
Takes the identical flags as `--strategy mt-convert-to-mw`, so you can copy the
migrate command verbatim and only change the entrypoint:

    poetry run python -m askar_tools.preflight_mt_convert \
        --uri postgres://<user>:<pass>@<host>:<port>/<admin-db> \
        --wallet-name <base/admin wallet name> \
        --wallet-key <base/admin wallet key> \
        --wallet-key-derivation-method <optional, default ARGON2I_MOD> \
        --multitenant-sub-wallet-name <optional, default multitenant_sub_wallet>

Extra flags from the migrate command line are ignored (parse_known_args), so
pasting the full command is safe.

ZERO-WRITE CONTRACT
-------------------
Every database/askar operation used here is read-only. Explicitly:
  * asyncpg.connect + SELECT-only queries (pg catalogs, information_schema).
  * aries_askar Store.open (opens, never creates -- recreate/create not used).
  * Store.scan / Session.fetch_all / Session.count / Store.list_profiles (reads).
It never calls create_database, remove_database, copy_to, create_profile,
set_default_profile, remove_profile, or any INSERT/UPDATE/DDL. No session is
ever committed.
"""

import argparse
import asyncio
import sys
from urllib.parse import urlparse

from askar_tools.key_methods import KEY_METHODS
from askar_tools.pg_connection import PgConnection

# ---------------------------------------------------------------------------
# Result plumbing
# ---------------------------------------------------------------------------

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"
SKIP = "SKIP"

_ORDER = {FAIL: 0, WARN: 1, SKIP: 2, PASS: 3}


class Report:
    """Accumulates check results and renders a final summary."""

    def __init__(self):
        self.results = []  # list of (status, name, detail)

    def add(self, status, name, detail=""):
        self.results.append((status, name, detail))
        icon = {PASS: "PASS", WARN: "WARN", FAIL: "FAIL", SKIP: "SKIP"}[status]
        line = f"  [{icon}] {name}"
        if detail:
            line += f"\n         {detail}"
        print(line, flush=True)

    def has_failures(self):
        return any(s == FAIL for s, _, _ in self.results)

    def summary(self):
        counts = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
        for status, _, _ in self.results:
            counts[status] += 1
        print("\n" + "=" * 68)
        print(
            "PRE-FLIGHT SUMMARY: "
            f"{counts[PASS]} pass, {counts[WARN]} warn, "
            f"{counts[FAIL]} fail, {counts[SKIP]} skipped"
        )
        if self.has_failures():
            print("VERDICT: NOT SAFE TO CONVERT -- resolve the FAIL items above.")
        elif counts[WARN]:
            print("VERDICT: Reachable, but review the WARN items before converting.")
        else:
            print("VERDICT: All access checks passed. Conversion path is reachable.")
        print("=" * 68)


# ---------------------------------------------------------------------------
# Arg parsing -- mirrors askar_tools.__main__.config() for mt-convert-to-mw
# ---------------------------------------------------------------------------


def config():
    """Parse the same args the migrate tool takes; ignore any extras."""
    parser = argparse.ArgumentParser("mt-convert-preflight")
    parser.add_argument("--uri", required=True, help="URI of the admin/base database.")
    parser.add_argument(
        "--wallet-name", required=True, help="Base/admin wallet name (also in URI)."
    )
    parser.add_argument(
        "--wallet-key", required=True, help="Key for the base/admin wallet."
    )
    parser.add_argument(
        "--wallet-key-derivation-method",
        default="ARGON2I_MOD",
        help="Key derivation method for the admin wallet. Default ARGON2I_MOD.",
    )
    parser.add_argument(
        "--multitenant-sub-wallet-name",
        default="multitenant_sub_wallet",
        help="Existing sub-wallet name. Default multitenant_sub_wallet.",
    )
    parser.add_argument(
        "--tenant-limit",
        type=int,
        default=0,
        help="If >0, only probe this many tenant profiles (0 = all).",
    )
    args, _ = parser.parse_known_args(sys.argv[1:])
    return args


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


async def _pg_connect(uri):
    """Connect via the tool's own PgConnection (mirrors conn.connect())."""
    conn = PgConnection(uri)
    await conn.connect()
    return conn


async def check_uri_and_connectivity(report, args):
    """Check 0/1: URI sanity + connectivity to admin DB and sub-wallet DB.

    Mirrors the converter's ConversionError guard (wallet name must be in the
    URI) and the derived sub-wallet URI (naive str.replace of the admin wallet
    name), plus conn.connect() to both databases.

    Returns (admin_conn, sub_uri) or (None, None) on hard failure.
    """
    parsed = urlparse(args.uri)
    if parsed.scheme != "postgres":
        report.add(
            WARN,
            "URI scheme",
            f"scheme is '{parsed.scheme}', not 'postgres'. This preflight targets "
            "the Crunchy/postgres path; sqlite is not probed here.",
        )
        return None, None

    # Converter guard: `if admin_wallet_name not in conn.uri: raise ConversionError`
    occurrences = args.uri.count(args.wallet_name)
    if occurrences == 0:
        report.add(
            FAIL,
            "Wallet name present in URI",
            f"'{args.wallet_name}' does not appear in the URI. The converter "
            "raises ConversionError and refuses to run. Fix --uri/--wallet-name.",
        )
        return None, None
    elif occurrences > 1:
        report.add(
            WARN,
            "Wallet name unique in URI",
            f"'{args.wallet_name}' appears {occurrences}x in the URI. The converter "
            "derives the sub-wallet URI with a naive str.replace, so a name that "
            "also matches the user/password/host will corrupt the derived sub URI.",
        )
    else:
        report.add(PASS, "Wallet name present in URI", "appears exactly once")

    # Admin DB connectivity
    try:
        admin_conn = await _pg_connect(args.uri)
    except Exception as e:
        report.add(
            FAIL,
            "Connect to admin database",
            f"{type(e).__name__}: {e}. Check VPN, host/port, credentials, TLS, "
            "and that the database name in the URI exists.",
        )
        return None, None

    try:
        row = await admin_conn._conn.fetchrow(
            "SELECT current_database() AS db, current_user AS usr, "
            "version() AS ver"
        )
        report.add(
            PASS,
            "Connect to admin database",
            f"db={row['db']} user={row['usr']} :: {row['ver'].split(' on ')[0]}",
        )
    except Exception as e:
        report.add(WARN, "Admin database identity query", f"{type(e).__name__}: {e}")

    # Sub-wallet DB connectivity (same host, name swapped -- exactly as converter)
    sub_uri = args.uri.replace(args.wallet_name, args.multitenant_sub_wallet_name)
    try:
        sub_conn = await _pg_connect(sub_uri)
        row = await sub_conn._conn.fetchrow("SELECT current_database() AS db")
        await sub_conn.close()
        report.add(
            PASS,
            "Connect to sub-wallet database",
            f"db={row['db']} (derived by swapping "
            f"'{args.wallet_name}' -> '{args.multitenant_sub_wallet_name}')",
        )
    except Exception as e:
        report.add(
            FAIL,
            "Connect to sub-wallet database",
            f"{type(e).__name__}: {e}. Expected database "
            f"'{args.multitenant_sub_wallet_name}' reachable on the same server. "
            "Without it there is nothing to convert.",
        )

    return admin_conn, sub_uri


async def check_createdb_privilege(report, admin_conn):
    """Check 2: the connecting role can CREATE DATABASE.

    The converter runs `CREATE DATABASE "<tenant>"` per tenant on this same
    connection/role. rolsuper implies the privilege too.
    """
    try:
        row = await admin_conn._conn.fetchrow(
            "SELECT rolcreatedb, rolsuper, rolcreaterole "
            "FROM pg_roles WHERE rolname = current_user"
        )
    except Exception as e:
        report.add(WARN, "CREATE DATABASE privilege", f"could not query: {e}")
        return

    if row and (row["rolcreatedb"] or row["rolsuper"]):
        report.add(
            PASS,
            "CREATE DATABASE privilege",
            f"connecting role has it "
            f"(rolcreatedb={row['rolcreatedb']}, rolsuper={row['rolsuper']})",
        )
    else:
        report.add(
            FAIL,
            "CREATE DATABASE privilege",
            "connecting role lacks CREATEDB (and is not superuser). Every tenant "
            "conversion does CREATE DATABASE and will fail. Connect as the askar "
            "admin_account (e.g. 'walletman', which is declared CREATEDB).",
        )


async def check_connection_budget(report, admin_conn):
    """Check (informational): max_connections vs. current usage."""
    try:
        max_row = await admin_conn._conn.fetchrow("SHOW max_connections")
        used = await admin_conn._conn.fetchval(
            "SELECT count(*) FROM pg_stat_activity"
        )
        report.add(
            PASS,
            "Connection budget (info)",
            f"max_connections={max_row['max_connections']}, currently in use={used}. "
            "Each converted tenant DB draws from this shared budget at runtime.",
        )
    except Exception as e:
        report.add(WARN, "Connection budget (info)", f"could not read: {e}")


def _import_askar(report):
    """Lazy import so pg-only checks still run if aries_askar is unavailable."""
    try:
        from aries_askar import Store

        return Store
    except Exception as e:
        report.add(
            FAIL,
            "aries_askar available",
            f"cannot import aries_askar ({type(e).__name__}: {e}). The wallet-access "
            "checks (open stores, read tenant profiles) cannot run. Run this in the "
            "same environment as the real migrate tool (poetry env / tool image).",
        )
        return None


async def check_wallets(report, args, sub_uri):
    """Checks 3-6: open admin + sub stores, enumerate tenants, read each profile.

    Mirrors MultiWalletConverter: open admin store (pass_key only), scan for
    wallet_record entries, open the sub-wallet store (pass_key only), then for
    each tenant open a read session on its profile. All read-only.
    """
    Store = _import_askar(report)
    if Store is None:
        return

    # Check 3: open the admin store (pass_key only, as the converter does)
    try:
        admin_store = await Store.open(args.uri, pass_key=args.wallet_key)
    except Exception as e:
        report.add(
            FAIL,
            "Open admin askar store",
            f"{type(e).__name__}: {e}. Wrong --wallet-key / derivation method, or "
            "the admin DB is not a valid askar store.",
        )
        return

    # Enumerate the tenants that WOULD be migrated
    try:
        scan = admin_store.scan()
        entries = await scan.fetch_all()
        wallet_records = [
            e.value_json for e in entries if e.category == "wallet_record"
        ]
        report.add(
            PASS,
            "Open admin store + enumerate tenants",
            f"{len(wallet_records)} tenant wallet_record(s) would be migrated.",
        )
    except Exception as e:
        report.add(FAIL, "Enumerate tenant wallet_records", f"{type(e).__name__}: {e}")
        await admin_store.close()
        return

    # Check 4: open the sub-wallet store (pass_key only, as the converter does)
    try:
        sub_store = await Store.open(sub_uri, pass_key=args.wallet_key)
    except Exception as e:
        report.add(
            FAIL,
            "Open sub-wallet askar store",
            f"{type(e).__name__}: {e}. Either this is not a multitenant "
            "(single-wallet-askar) store, or --multitenant-sub-wallet-name is wrong.",
        )
        await admin_store.close()
        return
    report.add(PASS, "Open sub-wallet askar store", f"opened '{args.multitenant_sub_wallet_name}'")

    # Cross-reference the profiles present in the sub store
    try:
        profiles = set(await sub_store.list_profiles())
    except Exception as e:
        report.add(WARN, "List sub-wallet profiles", f"{type(e).__name__}: {e}")
        profiles = None

    # Check 6 (read-only pre-check of CREATE DATABASE): target DB name collisions
    await _check_target_db_collisions(report, args, wallet_records)

    # Check 5: per-tenant profile read access + integrity
    await _probe_tenants(report, args, sub_store, wallet_records, profiles)

    await sub_store.close()
    await admin_store.close()


async def _check_target_db_collisions(report, args, wallet_records):
    """Read pg_database for each target name; the converter CREATE DATABASEs these."""
    # Reconnect on the admin DB purely to read the catalog (read-only).
    try:
        conn = await _pg_connect(args.uri)
    except Exception as e:
        report.add(WARN, "Target DB name collision check", f"could not reconnect: {e}")
        return

    try:
        existing = {
            r["datname"]
            for r in await conn._conn.fetch("SELECT datname FROM pg_database")
        }
    except Exception as e:
        report.add(WARN, "Target DB name collision check", f"{type(e).__name__}: {e}")
        await conn.close()
        return
    finally:
        await conn.close()

    collisions = []
    missing_name = 0
    for wr in wallet_records:
        name = wr.get("settings", {}).get("wallet.name")
        if not name:
            missing_name += 1
            continue
        if name in existing:
            collisions.append(name)

    detail_bits = []
    if collisions:
        detail_bits.append(
            f"{len(collisions)} target DB name(s) already exist and would make "
            f"CREATE DATABASE fail: {', '.join(sorted(collisions)[:10])}"
            + (" ..." if len(collisions) > 10 else "")
        )
    if missing_name:
        detail_bits.append(f"{missing_name} wallet_record(s) missing settings.wallet.name")

    if collisions or missing_name:
        report.add(FAIL if collisions else WARN, "Target DB name collision check", " | ".join(detail_bits))
    else:
        report.add(
            PASS,
            "Target DB name collision check",
            "no target tenant DB name already exists",
        )


async def _probe_tenants(report, args, sub_store, wallet_records, profiles):
    """Open a read session on each tenant profile and read a record count."""
    total = len(wallet_records)
    limit = args.tenant_limit if args.tenant_limit and args.tenant_limit > 0 else total
    to_probe = wallet_records[:limit]

    ok = 0
    read_failures = []
    profile_mismatches = []

    for wr in to_probe:
        settings = wr.get("settings", {})
        wallet_id = settings.get("wallet.id")
        wallet_name = settings.get("wallet.name", "<no-name>")

        if not wallet_id:
            read_failures.append(f"{wallet_name} (no wallet.id in record)")
            continue

        if profiles is not None and wallet_id not in profiles:
            profile_mismatches.append(f"{wallet_name} ({wallet_id})")
            continue

        try:
            # Read-only: open a session pinned to this tenant's profile and count.
            # Proves the profile exists and its records decrypt/read under the store key.
            async with sub_store.session(profile=wallet_id) as session:
                await session.count(category="connection")
            ok += 1
        except Exception as e:
            read_failures.append(f"{wallet_name} ({wallet_id}): {type(e).__name__}: {e}")

    # Report per-tenant access
    if read_failures:
        shown = "; ".join(read_failures[:5]) + (" ..." if len(read_failures) > 5 else "")
        report.add(
            FAIL,
            "Read tenant wallet profiles",
            f"{ok}/{len(to_probe)} readable; {len(read_failures)} failed: {shown}",
        )
    else:
        note = "" if limit >= total else f" (probed {limit} of {total})"
        report.add(
            PASS, "Read tenant wallet profiles", f"all {ok} probed profiles readable{note}"
        )

    # Report integrity: wallet_records whose profile is absent from the sub store
    if profile_mismatches:
        shown = ", ".join(profile_mismatches[:10]) + (
            " ..." if len(profile_mismatches) > 10 else ""
        )
        report.add(
            FAIL,
            "Tenant record <-> profile integrity",
            f"{len(profile_mismatches)} wallet_record(s) have no matching profile in "
            f"the sub-wallet store; copy_to would fail for these: {shown}",
        )
    elif profiles is not None:
        report.add(
            PASS,
            "Tenant record <-> profile integrity",
            "every probed wallet_record has a matching sub-wallet profile",
        )

    # Sanity: the derivation-method flag maps to a known method (info)
    if args.wallet_key_derivation_method not in KEY_METHODS:
        report.add(
            WARN,
            "Key derivation method recognized",
            f"'{args.wallet_key_derivation_method}' not in {list(KEY_METHODS)}; "
            "the converter maps per-record methods, but this default is unusual.",
        )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


async def run(args):
    """Run all read-only pre-flight checks and print a report."""
    report = Report()
    print("mt-convert-to-mw PRE-FLIGHT (read-only; no writes performed)\n")

    admin_conn, sub_uri = await check_uri_and_connectivity(report, args)
    if admin_conn is None:
        report.summary()
        return 1

    await check_createdb_privilege(report, admin_conn)
    await check_connection_budget(report, admin_conn)
    await admin_conn.close()

    if sub_uri is not None:
        await check_wallets(report, args, sub_uri)

    report.summary()
    return 1 if report.has_failures() else 0


def entrypoint():
    """CLI entrypoint."""
    args = config()
    rc = asyncio.run(run(args))
    sys.exit(rc)


if __name__ == "__main__":
    entrypoint()
