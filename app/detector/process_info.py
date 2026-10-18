import os

import psutil


def get_process_metadata():

    try:

        process = psutil.Process(
            os.getpid()
        )

        return {
            "pid": process.pid,
            "name": process.name(),
            "exe": process.exe(),
            "cpu_percent": process.cpu_percent(
                interval=0.1
            ),
            "memory_percent": round(
                process.memory_percent(),
                2
            )
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess
    ) as error:

        print(
            f"[PROCESS INFO ERROR] {error}"
        )

        return None