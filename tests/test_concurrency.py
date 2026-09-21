"""Real POSIX process/lock tests, using synthetic tokens and no network."""

import argparse
import contextlib
import io
import multiprocessing
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from etsy_oauth_pkce import cli
from etsy_oauth_pkce.credentials import Credentials
from etsy_oauth_pkce.session import EtsySession
from etsy_oauth_pkce.store import FileTokenStore
from etsy_oauth_pkce.tokens import Token

from .fakes import make_token


class ObservedStore(FileTokenStore):
    def __init__(self, path, attempted):
        super().__init__(path)
        self.attempted = attempted

    @contextlib.contextmanager
    def lock(self):
        self.attempted.set()
        with super().lock():
            yield


class HeldEndpoint:
    def __init__(self, count, entered, release):
        self.count, self.entered, self.release = count, entered, release

    def refresh(self, client_id, refresh_token):
        with self.count.get_lock():
            self.count.value += 1
        self.entered.set()
        if not self.release.wait(10):
            raise RuntimeError("test release timed out")
        return make_token(10_000, access="123.new")


def refresh_worker(path, count, entered, release, attempted, results):
    session = EtsySession(Credentials("fake", "fake"), ObservedStore(Path(path), attempted),
                          token_endpoint=HeldEndpoint(count, entered, release), clock=lambda: 100)
    results.put(session.access_token())


def mutation_worker(operation, path, attempted, done):
    store = ObservedStore(Path(path), attempted)
    with mock.patch.object(cli, "_store", return_value=store), contextlib.redirect_stdout(io.StringIO()):
        if operation == "logout":
            cli.cmd_logout(argparse.Namespace(home=Path(path).parent))
        else:
            args = cli._parser().parse_args(["--home", str(Path(path).parent), "login", "--callback", "paste"])
            token = Token("456.login", "456.refresh", 10_000, ("shops_r",), 456)
            with mock.patch.object(cli.credentials_module, "load", return_value=Credentials("fake", "fake")), \
                    mock.patch.object(cli, "_paste_code", return_value="fake"), \
                    mock.patch.object(cli, "TokenEndpoint") as endpoint:
                endpoint.return_value.exchange.return_value = token
                cli.cmd_login(args)
    done.set()


class ProcessLockTests(unittest.TestCase):
    def setUp(self):
        self.context = multiprocessing.get_context("spawn")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "token.json")
        self.store = FileTokenStore(Path(self.path))
        self.store.save(make_token(1))
        self.count = self.context.Value("i", 0)
        self.entered = self.context.Event()
        self.release = self.context.Event()
        self.results = self.context.Queue()

    def start(self, target, args):
        process = self.context.Process(target=target, args=args)
        process.start()

        def cleanup():
            self.release.set()
            process.join(10)
            if process.is_alive():
                process.terminate()
                process.join(5)

        self.addCleanup(cleanup)
        return process

    def refresh(self):
        attempted = self.context.Event()
        process = self.start(refresh_worker, (self.path, self.count, self.entered, self.release, attempted, self.results))
        return process, attempted

    def finish(self, *processes):
        self.release.set()
        for process in processes:
            process.join(10)
            self.assertEqual(process.exitcode, 0)

    def test_parallel_refresh_only_exchanges_once(self):
        first, _ = self.refresh()
        self.assertTrue(self.entered.wait(10))
        second, attempted = self.refresh()
        self.assertTrue(attempted.wait(10))
        self.assertEqual(self.count.value, 1)
        self.finish(first, second)
        self.assertEqual([self.results.get(timeout=2) for _ in range(2)], ["123.new", "123.new"])
        self.assertEqual(self.count.value, 1)
        self.assertEqual(self.store.load().access_token, "123.new")

    def check_mutation_waits_for_refresh(self, operation):
        refresher, _ = self.refresh()
        self.assertTrue(self.entered.wait(10))
        attempted, done = self.context.Event(), self.context.Event()
        mutation = self.start(mutation_worker, (operation, self.path, attempted, done))
        self.assertTrue(attempted.wait(10))
        self.assertFalse(done.wait(0.1))
        self.finish(refresher, mutation)
        self.assertTrue(done.is_set())

    def test_logout_is_not_undone_by_inflight_refresh(self):
        self.check_mutation_waits_for_refresh("logout")
        self.assertIsNone(self.store.load())

    def test_login_is_not_overwritten_by_inflight_refresh(self):
        self.check_mutation_waits_for_refresh("login")
        self.assertEqual(self.store.load().user_id, 456)
