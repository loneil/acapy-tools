"""Module contains the Repairer class."""

from aries_askar import Store

from .key_methods import KEY_METHODS
from .pg_connection import PgConnection
from .sqlite_connection import SqliteConnection


class Repairer:
    """Repair inconsistent wallet records in a wallet."""

    def __init__(
        self,
        conn: SqliteConnection | PgConnection,
        wallet_name: str,
        wallet_key: str,
        wallet_key_derivation_method: str = "ARGON2I_MOD",
    ) -> None:
        self.conn = conn
        self.wallet_name = wallet_name
        self.wallet_key = wallet_key
        self.wallet_key_derivation_method = wallet_key_derivation_method

    async def run(self):
        """Run the repair process."""
        await self.repair()

    async def repair(self):
        """Repair inconsistent wallet records."""
        admin_store = await self._open_store()
        try:
            for profile in await admin_store.list_profiles():
                await self._repair_profile(profile)
        finally:
            await admin_store.close()
            await self.conn.close()

    async def _open_store(self, profile: str | None = None):
        key_method = KEY_METHODS.get(self.wallet_key_derivation_method)
        if not key_method:
            raise ValueError(
                f"Unsupported wallet key derivation method: {self.wallet_key_derivation_method}"
            )
        return await Store.open(
            self.conn.uri,
            pass_key=self.wallet_key,
            key_method=key_method,
            profile=profile,
        )

    async def _repair_profile(self, profile: str):
        print(f"Repairing wallet {self.wallet_name} profile {profile}")
        store = await self._open_store(profile)
        try:
            async with store.transaction() as txn:
                await self._repair_revocation_registries(txn)
                await self._repair_credential_definitions(txn)
                await txn.commit()
        finally:
            await store.close()

    async def _repair_revocation_registries(self, txn):
        for record in await txn.fetch_all("revocation_reg_def"):
            if await txn.fetch("revocation_reg_def_private", name=record.name):
                continue
            print(f"Removing broken revocation registry {record.name}")
            try:
                issuer = await txn.fetch_all(
                    "issuer_rev_reg",
                    tag_filter={"revoc_reg_id": record.name},
                )
                for rec in issuer:
                    await self._remove_if_exists(txn, "issuer_rev_reg", rec.name)
                await self._remove_if_exists(txn, "revocation_reg_info", record.name)
                await self._remove_if_exists(txn, "revocation_reg", record.name)
                await self._remove_if_exists(txn, "revocation_reg_def", record.name)
            except Exception as e:
                print(f"Failed removing revocation registry {record.name}: {e}")

    async def _repair_credential_definitions(self, txn):
        for record in await txn.fetch_all("credential_def"):
            private = await txn.fetch("credential_def_private", name=record.name)
            key = await txn.fetch("credential_def_key_proof", name=record.name)
            if private and key:
                continue
            print(f"Removing broken credential definition {record.name}")
            try:
                sent = await txn.fetch_all(
                    "cred_def_sent",
                    tag_filter={"cred_def_id": record.name},
                )
                await self._remove_if_exists(txn, "credential_def", record.name)
                if not key:
                    await self._remove_if_exists(
                        txn, "credential_def_private", record.name
                    )
                await self._remove_if_exists(txn, "credential_def_key_proof", record.name)
                for rec in sent:
                    await self._remove_if_exists(txn, "cred_def_sent", rec.name)
            except Exception as e:
                print(f"Failed removing credential definition {record.name}: {e}")

    async def _remove_if_exists(self, txn, category: str, name: str):
        try:
            await txn.remove(category, name)
        except Exception as e:
            print(f"Unable to remove {category}/{name}: {e}")
