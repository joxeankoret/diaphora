#!/usr/bin/python3

import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, wait
from multiprocessing.managers import BaseManager
from pathlib import Path
from queue import Queue
from random import randrange
from time import time
from typing import Optional, Tuple, cast

IDA = os.getenv("IDADIR") + "idat64"
DIAPHORA = str(Path("diaphora.py").resolve())
DIAPHORA_DIR = str(Path(".").resolve())

###############################################
# Database merge taken from
# https://stackoverflow.com/a/68526717


def merge_databases(db1: str, db2: str) -> None:
    print(f"Merging {db2} into {db1}")
    con3 = sqlite3.connect(db1)

    con3.execute("ATTACH '" + db2 + "' as dba")

    con3.execute("BEGIN")
    for row in con3.execute("SELECT * FROM dba.sqlite_master WHERE type='table'"):
        combine = "INSERT OR IGNORE INTO " + row[1] + " SELECT * FROM dba." + row[1]
        con3.execute(combine)
    con3.commit()
    con3.execute("detach database dba")
    con3.close()


###############################################


def get_idb(target: Path) -> Path:
    target_idb = target.parent / (target.name + ".i64")
    if not target_idb.exists():
        subprocess.run(
            [IDA, "-Llog.txt", "-B", str(target)],
            env={
                "TVHEADLESS": "1",
                "HOME": os.getenv("HOME", ""),
                "IDAUSR": os.getenv("IDAUSR", ""),
            },
        )
    return target_idb


def start_exporter(args: Tuple[Path, Path, int, int, int, bytes]) -> int:
    tmpdir, source_idb, worker_id, nbr_of_workers, port, authkey = args
    target = tmpdir / (source_idb.name[: -len(".i64")] + str(worker_id) + ".i64")
    shutil.copyfile(source_idb, target)
    os.system(
        "TVHEADLESS=1 "
        f'PYTHON_PATH=$PYTHON_PATH:"{DIAPHORA_DIR}" '
        "~/idapro-8.2/./idat64 -a -A "
        f'-S"{DIAPHORA} {worker_id} {nbr_of_workers} {port} {b64encode(authkey).decode("ASCII")}" '
        f"-Llog.txt "
        f"{target}"
    )
    target.unlink()
    print(f"Worker {worker_id} done")
    return worker_id


class QueueManager(BaseManager):
    pass


def start_queues() -> Tuple[QueueManager, int, bytes]:
    job_queue: Queue[Tuple[int, int]] = Queue()
    report_queue: Queue[int] = Queue()

    QueueManager.register("get_job_queue", callable=lambda: job_queue)
    QueueManager.register("get_report_queue", callable=lambda: report_queue)

    m: Optional[QueueManager] = None
    port = randrange(49152, 65536)
    authkey = secrets.token_bytes()

    while m is None:
        try:
            m = QueueManager(address=("localhost", port), authkey=authkey)
            m.start()
        except Exception:
            m = None
            port = randrange(49152, 65536)

    return m, port, authkey


def merge_while_exporting(
    qm: QueueManager, number_of_workers: int, number_of_jobs: int
) -> Tuple[Path, int]:
    # merge as soon as exports are done and return path to merged db
    assert number_of_workers > 0
    db_files = [
        str(tmpdir / f"{target.name}{i}.sqlite") for i in range(number_of_workers)
    ]
    remaining_workers = {i for i in range(number_of_workers)}
    main_worker: Optional[int] = None

    while remaining_workers:
        worker_id, report = cast(Tuple[int, int], qm.get_report_queue().get())
        if report >= 0:
            print(f"Job {report} done by worker {worker_id}")
            continue

        if main_worker is None:
            main_worker = worker_id
        else:
            merge_databases(db_files[main_worker], db_files[worker_id])
        remaining_workers.discard(worker_id)

    # merge into last worker db
    assert main_worker is not None

    return Path(db_files[main_worker]), main_worker


if __name__ == "__main__":
    start = time()
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file> [<nbr workers>] [<nbr jobs>]")
    target = Path(sys.argv[1]).resolve()
    target_idb = get_idb(target)
    print(f"idb retrieved in {time() - start:.3f} seconds")

    number_of_workers = (os.cpu_count() or 4) - 1
    if len(sys.argv) > 2:
        number_of_workers = int(sys.argv[2])
    number_of_jobs = 2 * number_of_workers
    if len(sys.argv) > 3:
        number_of_jobs = int(sys.argv[3])

    assert number_of_jobs >= number_of_workers > 0

    queue_manager, port, authkey = start_queues()

    print(f"Starting {number_of_jobs} jobs on {number_of_workers} workers")

    with tempfile.TemporaryDirectory(dir=target.parent) as tmpdirname:
        tmpdir = Path(tmpdirname)
        print("Working in ", tmpdir)

        with ThreadPoolExecutor(max_workers=number_of_workers) as pool:
            futures = [
                pool.submit(
                    start_exporter,
                    (tmpdir, target_idb, i, number_of_workers, port, authkey),
                )
                for i in range(number_of_workers)
            ]

            # send jobs
            for i in range(number_of_jobs):
                print(f"Sending job {i} of {number_of_jobs}")
                queue_manager.get_job_queue().put((i, number_of_jobs))

            # send kill switches
            for i in range(number_of_workers):
                print(f"Sending killswitch {i}")
                queue_manager.get_job_queue().put((-1, number_of_jobs))

            # Start merging results asap
            merged_database, last_worker = merge_while_exporting(
                queue_manager, number_of_workers, number_of_jobs
            )
            print(f"Functions exported in {time() - start:.3f} seconds")

            wait(futures)

        # Run diaphora one more time to get global info
        print("Finalizing database...")
        (merged_database.parent / (merged_database.name + "-crash")).touch()
        start_exporter((tmpdir, target_idb, last_worker, last_worker, port, authkey))
        print(f"Database exported in {time() - start:.3f} seconds")
        merged_database.rename(target.parent / f"{target.name}.sqlite")

    queue_manager.shutdown()
