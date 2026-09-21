#!/usr/bin/env python3
"""Deploy the shielded pool on a real local chain and put a deposit through it.

Every number this project has ever quoted -- gas, roots, refusals, ceilings --
was measured in the sandbox executor.  That executor is the code a validator
runs, but running it is not running a chain: it has no block production, no
message queue, no forward fees and no account storage.  So the claim "the pool
works" has never been tested against the thing it will actually live in.

This harness closes that.  It owns a fresh single-validator localnet, deploys
the exact state the frozen manifest names, sends one real deposit from a real
wallet, and requires the chain to arrive at the commitment root the circuit
predicted *before* the message was sent.

Nothing here re-implements the pool.  The code, the state, the deposit body and
the expected root all come out of `onchain_fixture`, which builds them from the
same sources the suites compile.  This script only carries bytes to a node and
reads answers back.

Run from the repository:

    uv run python scripts/shielded-pool-onchain-e2e.py

It needs a build with the node binaries (`ninja validator-engine dht-server
lite-client`) and the Rust fixture generator; pass --build-dir for a build tree
elsewhere, and --fixture to reuse one that has already been generated.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))

from contract import WalletV1, tos  # noqa: E402
from pytosiq_core import (  # noqa: E402
    Address,
    Cell,
    InternalMsgInfo,
    MessageAny,
    StateInit,
    WalletMessage,
)
from tostester.install import Install  # noqa: E402
from tostester.network import FullNode, Network, StartOptions  # noqa: E402

TOS = 1_000_000_000

# Global version 18 is where POSEIDON2_PATH7 lives, and 17 is where the
# permutation and the seven-input hash do.  A chain below 18 cannot run this
# contract at all: the instructions are not merely absent, they are refused.
GLOBAL_VERSION = 18

# A real internal message pays a forward fee out of its own value, so the
# msg_value the contract sees is less than the value the wallet sent.  The
# sandbox charges no forward fee, which is why every funding figure measured
# there is a lower bound on what a sender must attach.  This is the allowance
# on top of the fixture's minimum; the run reports what was actually consumed
# so the number can stop being a guess.
FORWARD_FEE_ALLOWANCE = 50_000_000


class Failed(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[onchain] {message}", flush=True)


# ---------------------------------------------------------------------------
# The fixture: the bytes a node needs, built by the crosscheck crate.


def build_fixture(out: Path, build: Path) -> Path:
    log("building the deployment fixture from the crosscheck crate ...")
    crate = REPO / "tools/shielded-pool-circuit/crosscheck"
    cargo = Path.home() / ".cargo/bin/cargo"
    environment = dict(os.environ)
    # `TOS_ROOT` is where the FunC compiler and the Fift assembler are looked
    # for -- `build/crypto/func` under it -- not where the sources are. Those
    # come from the crate itself. Pointing it at this checkout when the build
    # lives elsewhere finds some other tree's toolchain, and an older Fift
    # answers `POSEIDON2_HASH7:-?` instead of assembling it.
    environment["TOS_ROOT"] = str(build.parent)
    environment["CARGO_TERM_COLOR"] = "never"
    result = subprocess.run(
        [str(cargo), "run", "--release", "--bin", "onchain_fixture", "--",
         str(REPO), str(out)],
        cwd=crate,
        env=environment,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise Failed(f"onchain_fixture failed:\n{result.stdout}\n{result.stderr}")
    return out


def load_fixture(directory: Path) -> dict:
    fixture = json.loads((directory / "fixture.json").read_text())
    names = ["code.boc", "data.boc", fixture["destination"]["code"]]
    names += [step["body"] for step in fixture["steps"]]
    for name in names:
        path = directory / name
        if not path.exists():
            raise Failed(f"the fixture has no {name}")
    return fixture


def cell_from(path: Path) -> Cell:
    return Cell.one_from_boc(path.read_bytes())


# ---------------------------------------------------------------------------
# The chain: get-methods through the lite client, because that is the interface
# a wallet or an explorer would use.


class LiteClient:
    def __init__(self, binary: Path, config: Path) -> None:
        self.binary = binary
        self.config = config

    def run(self, command: str, timeout: float = 30.0) -> str:
        result = subprocess.run(
            [str(self.binary), "-C", str(self.config), "-v", "0", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise Failed(f"lite-client {command!r} exited {result.returncode}:\n{result.stderr}")
        return result.stdout

    def get_method(self, address: str, method: str) -> str:
        """One field element off the top of a get-method's stack, as decimal."""
        output = self.run(f"runmethod {address} {method}")
        match = re.search(r"result:\s*\[\s*([0-9-]+)\s*\]", output)
        if not match:
            raise Failed(f"{method} returned nothing the harness could read:\n{output}")
        return match.group(1)

    def account(self, address: str) -> str:
        return self.run(f"getaccount {address}")

    def transaction_gas(self, address: str, lt: str, transaction_hash: str) -> int | None:
        """The gas the chain charged, out of the dumped transaction.

        The JSON-RPC reports a fee and the number of VM steps but not the gas,
        and the gas is the number every ceiling in section 14 is expressed in.
        """
        output = self.run(f"lasttransdump {address} {lt} {transaction_hash} 1")
        match = re.search(r"gas_used:\(var_uint\s+len:\d+\s+value:(\d+)\)", output)
        if not match:
            match = re.search(r"gas_used[^0-9]{0,40}(\d+)", output)
        return int(match.group(1)) if match else None

    def account_exists(self, address: str) -> bool:
        output = self.account(address)
        self.last_account = output
        return "account_none" not in output and "account_active" in output


def rpc(endpoint: str, method: str, **params):
    """The other read path. The lite client speaks the lite protocol; this is
    the HTTP interface a wallet or an explorer would use, and the two agreeing
    is worth more than either alone."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        f"http://{endpoint}/jsonRPC", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode())


def describe_transaction(rpc_address: str, account: str) -> dict | None:
    """What the chain charged for the last transaction on that account."""
    answer = rpc(rpc_address, "getTransactions", address=account, limit=1)
    result = answer.get("result")
    if not result:
        return None
    transaction = result[0] if isinstance(result, list) else result
    return transaction


# ---------------------------------------------------------------------------


def internal(source: Address, destination: Address, value: int, body: Cell,
             init: StateInit | None, bounce: bool) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=bounce,
                bounced=False,
                src=source,
                dest=destination,
                value=tos(value / TOS),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=init,
            body=body,
        ),
    )


async def wait_for(what: str, predicate, timeout: float, interval: float = 1.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as error:  # a chain that is not ready answers by failing
            last = error
        await asyncio.sleep(interval)
    raise Failed(f"timed out waiting for {what}" + (f": {last}" if last else ""))


def compare(name: str, expected: str, produced: str, failures: list[str]) -> None:
    verdict = "ok" if expected == produced else "DISAGREES"
    log(f"  {name:<26} {produced:<78} {verdict}")
    if expected != produced:
        failures.append(f"{name}: the chain says {produced}, the circuit predicted {expected}")


def report_cost(lite, rpc_address, account, step, workdir, failures) -> None:
    """What the chain charged for the message just sent, against what the
    sandbox charged for the same bytes.

    Every gas figure this project quotes comes from the sandbox, on the
    understanding that it is the code a validator runs. This is the one place
    the understanding is checked rather than assumed.
    """
    transaction = describe_transaction(rpc_address, account)
    if transaction is None:
        log("  the JSON-RPC returned no transaction for the pool account")
        return
    name = step["body"].replace(".boc", "")
    (workdir / f"{name}-transaction.json").write_text(json.dumps(transaction, indent=2))

    compute = transaction.get("compute", {})
    action = transaction.get("action", {})
    log(f"  {'fee charged':<34} {transaction.get('fee')}")
    log(f"  {'compute exit code':<34} {compute.get('exit_code')}")
    if transaction.get("aborted"):
        failures.append(f"{step['name']}: the transaction was aborted")
    if compute.get("exit_code") not in (0, None):
        failures.append(f"{step['name']}: the compute phase exited {compute.get('exit_code')}")
    if action and action.get("success") is False:
        failures.append(f"{step['name']}: the action phase failed, code {action.get('result_code')}")

    identifier = transaction.get("transaction_id", {})
    lt = identifier.get("lt")
    digest = identifier.get("hash")
    if not (lt and digest):
        return
    gas = lite.transaction_gas(account, str(lt), base64.b64decode(digest).hex())
    if gas is None:
        log("  the transaction dump did not say how much gas was used")
        return
    ceiling = int(step["gas_ceiling"])
    sandbox = int(step["sandbox_gas_used"])
    log(f"  {'gas_used, on the chain':<34} {gas}")
    log(f"  {'gas_used, in the sandbox':<34} {sandbox}")
    log(f"  {'the ceiling it ran under':<34} {ceiling}")
    if gas > ceiling:
        failures.append(
            f"{step['name']}: the chain charged {gas} gas under a ceiling of {ceiling}, "
            f"so SETGASLIMIT did not bind"
        )
    if gas != sandbox:
        failures.append(
            f"{step['name']}: the chain charged {gas} gas and the sandbox charged {sandbox} "
            f"for the same message. Every gas figure in this project comes from the sandbox, "
            f"so the difference is the error bar on all of them."
        )


async def run(args) -> int:
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="tos-shielded-"))
    build = Path(args.build_dir)
    fixture_dir = (
        Path(args.fixture) if args.fixture else build_fixture(workdir / "fixture", build)
    )
    fixture = load_fixture(fixture_dir)
    # Section 9's intent window is an hour, so a fixture is perishable: its
    # transact carries a `valid_until` the contract compares against the
    # chain's clock. Refused here rather than on the chain, where it would
    # look like a proof failure.
    remaining = int(fixture["valid_until"]) - int(time.time())
    if remaining < args.step_timeout + 60:
        raise Failed(
            f"this fixture's intent expires in {remaining}s, which is not enough to bring a "
            f"chain up and send three messages. Rebuild it: drop --fixture, or rerun "
            f"onchain_fixture."
        )
    log(f"the fixture's intent is good for another {remaining}s")
    address_text = fixture["address"]
    log(f"pool address {address_text}")
    log(f"state hash   {fixture['state_hash']}")

    install = Install(build, REPO)
    lite_binary = build / "lite-client/lite-client"
    if not lite_binary.exists():
        raise Failed(f"{lite_binary} is missing; run ninja lite-client")

    chain_dir = workdir / "chain"
    shutil.rmtree(chain_dir, ignore_errors=True)
    chain_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    failures: list[str] = []

    async with Network(install, chain_dir, base_port=args.base_port) as network:
        # Set before the first node starts: the zerostate is generated lazily,
        # and the global version is part of it.
        network.config.global_version = GLOBAL_VERSION
        # And the deployed chain's fee schedule, not the cheap test one.
        # Two things depend on it. Every gas ceiling in section 14 was derived
        # under ConfigParam 21 as `gen-zerostate.fif` writes it, so a fee
        # measured under the test schedule is a fee on a chain nobody runs;
        # and the test schedule grants a transaction 1,000,000 gas, which is
        # below the pool's own transact ceiling of 1,460,000 -- under it a
        # withdrawal is not slow, it is refused.
        network.config.deployment_fee_schedule = True
        # The chain's global id is eight of the eighteen public inputs, by way
        # of the execution domain. The fixture was proved for one value, so
        # the chain is built with that value; a proof made for another chain
        # is refused, and would look like a broken proof rather than a
        # mismatched chain.
        network.config.global_id = int(fixture["global_id"])
        log(f"localnet at global_version={network.config.global_version}, "
            f"global_id={network.config.global_id}, deployment fee schedule")

        dht = network.create_dht_node()
        node: FullNode = network.create_full_node()
        node.make_initial_validator()
        node.announce_to(dht)

        lite_config = chain_dir / "lite-client.json"
        lite_config.write_text(node.liteserver_config.to_json())
        lite = LiteClient(lite_binary, lite_config)

        rpc_address = f"127.0.0.1:{args.base_port + 500}"
        tasks = [
            asyncio.create_task(dht.run()),
            asyncio.create_task(node.run(StartOptions(args=["--json-rpc-address", rpc_address]))),
        ]
        try:
            log("waiting for masterchain block #1 ...")
            await asyncio.wait_for(network.wait_mc_block(seqno=1), timeout=args.boot_timeout)
            log("the chain is producing blocks")

            client = await node.toslib_client()
            faucet: WalletV1 = network.zerostate.main_wallet(client)
            destination = Address(address_text)

            # --- deploy ----------------------------------------------------
            code = cell_from(fixture_dir / "code.boc")
            data = cell_from(fixture_dir / "data.boc")
            init = StateInit(split_depth=None, special=None, code=code, data=data, library=None)
            deploy_value = int(fixture["deploy_value_nanotos"])
            log(f"deploying with {deploy_value/TOS:.9f} TOS ...")
            await faucet.send(
                internal(faucet.address, destination, deploy_value, Cell.empty(), init, bounce=False)
            )
            try:
                await wait_for(
                    "the pool account to become active",
                    lambda: lite.account_exists(address_text),
                    timeout=args.step_timeout,
                )
            except Failed:
                log("the deploy did not take. What the chain says about the account:")
                print(getattr(lite, "last_account", "(nothing was read)"))
                log("and about the faucet, to show the message left at all:")
                print(lite.account(faucet.address.to_str()))
                raise
            log("the pool is deployed and active on the chain")

            # The state a real node holds must be the state the manifest
            # freezes.  Reading the roots back is how that is checked without
            # trusting the deploy path.
            log("genesis, as the chain holds it:")
            expected = fixture["expected_at_genesis"]
            compare("commitment_root", expected["commitment_root"],
                    lite.get_method(address_text, "commitment_root"), failures)
            compare("nullifier_root", expected["nullifier_root"],
                    lite.get_method(address_text, "nullifier_root"), failures)
            compare("commitment_next_index", "0",
                    lite.get_method(address_text, "commitment_next_index"), failures)
            compare("native_liability", "0",
                    lite.get_method(address_text, "native_liability"), failures)

            # --- the scenario ----------------------------------------------
            #
            # Three messages: two deposits and one proved withdrawal. Each one
            # is compared against what the circuit said the chain would hold
            # afterwards, computed before any of them was sent.
            destination_address = Address(fixture["destination"]["address"])
            log(f"deploying the payout destination {fixture['destination']['address']} ...")
            await faucet.send(
                internal(
                    faucet.address,
                    destination_address,
                    int(fixture["destination"]["deploy_value_nanotos"]),
                    Cell.empty(),
                    StateInit(
                        split_depth=None,
                        special=None,
                        code=cell_from(fixture_dir / fixture["destination"]["code"]),
                        data=Cell.empty(),
                        library=None,
                    ),
                    bounce=False,
                )
            )
            await wait_for(
                "the destination account to become active",
                lambda: lite.account_exists(fixture["destination"]["address"]),
                timeout=args.step_timeout,
            )

            for step in fixture["steps"]:
                expect = step["expect"]
                body = cell_from(fixture_dir / step["body"])
                value = int(step["value_nanotos"]) + args.fee_allowance
                log(f"{step['name']}: attaching {value/TOS:.9f} TOS ...")
                await faucet.send(
                    internal(faucet.address, destination, value, body, None, bounce=True)
                )
                try:
                    await wait_for(
                        f"{step['name']} to be accepted",
                        lambda expect=expect: lite.get_method(
                            address_text, "commitment_next_index"
                        ) == str(expect["commitment_next_index"]),
                        timeout=args.step_timeout,
                    )
                except Failed:
                    log(f"{step['name']} did not land. Dumping what the chain has:")
                    for who, account in (("pool", address_text),
                                         ("wallet", faucet.address.to_str())):
                        answer = rpc(rpc_address, "getTransactions", address=account, limit=3)
                        path = workdir / f"failure-{who}-transactions.json"
                        path.write_text(json.dumps(answer, indent=2))
                        log(f"  {path}")
                        for transaction in answer.get("result", []):
                            log(
                                f"  {who} lt={transaction.get('transaction_id', {}).get('lt')} "
                                f"fee={transaction.get('fee')} "
                                f"aborted={transaction.get('aborted')} "
                                f"compute={transaction.get('compute')} "
                                f"in_value={transaction.get('in_msg', {}).get('value')} "
                                f"out={len(transaction.get('out_msgs', []))}"
                            )
                    raise
                log(f"after {step['name']}:")
                for field in ("commitment_root", "commitment_next_index", "nullifier_root",
                              "nullifier_next_index", "native_liability"):
                    if field in expect:
                        compare(field, str(expect[field]),
                                lite.get_method(address_text, field), failures)
                report_cost(lite, rpc_address, address_text, step, workdir, failures)

            # The money left the pool and arrived. A withdrawal that moved
            # every root correctly and paid nobody would pass every check
            # above, so the destination's balance is read as well.
            paid = int(fixture["destination"]["expects_nanotos"])
            balance = rpc(rpc_address, "getAddressBalance",
                          address=fixture["destination"]["address"]).get("result")
            log(f"the destination holds {int(balance)/TOS:.9f} TOS")
            if int(balance) < paid:
                failures.append(
                    f"the destination holds {balance} nanotos, which is less than the "
                    f"{paid} the withdrawal was supposed to pay it"
                )
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    if failures:
        log("FAILED")
        for failure in failures:
            log(f"  {failure}")
        return 1
    log("the chain agrees with the circuit at every point checked")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default=os.environ.get("TOS_BUILD_DIR", str(REPO / "build")))
    parser.add_argument("--fixture", default=None,
                        help="a directory onchain_fixture has already written")
    parser.add_argument("--workdir", default=None)
    parser.add_argument("--base-port", type=int, default=21000)
    parser.add_argument("--boot-timeout", type=float, default=180.0)
    parser.add_argument("--step-timeout", type=float, default=120.0)
    parser.add_argument("--fee-allowance", type=int, default=FORWARD_FEE_ALLOWANCE)
    args = parser.parse_args()
    try:
        return asyncio.run(run(args))
    except Failed as error:
        log(f"FAILED: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
